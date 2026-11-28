"""Controlled same-process Contacts retire matrix; prints no credential material."""
import http.client, json, os, subprocess, tempfile, time

OPERATOR = "inert-lab-operator"
ORIGIN = "https://contacts.example.invalid"

def req(port, method, path, data=None, cookie=None, csrf=False, bearer=None, origin=ORIGIN):
    headers = {"X-Operator": OPERATOR}
    if data is not None: headers["Content-Type"] = "application/json"
    if cookie: headers["Cookie"] = cookie
    if csrf:
        headers["X-Echo-Request"] = "1"
        headers["Origin"] = origin
    if bearer: headers["Authorization"] = "Bearer " + bearer
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, path, None if data is None else json.dumps(data), headers)
    response = conn.getresponse()
    body, set_cookie = response.read().decode(), response.getheader("Set-Cookie")
    conn.close()
    try: parsed = json.loads(body)
    except json.JSONDecodeError: parsed = None
    return response.status, parsed, (set_cookie.split(";", 1)[0] if set_cookie else None)

def start(port, cert=None, mode="off"):
    env = os.environ.copy()
    env["ASPNETCORE_URLS"] = f"http://127.0.0.1:{port}"
    env["DataProtection__Rotation"] = mode
    if cert: env["DataProtection__CertificatePath"] = cert
    else: env.pop("DataProtection__CertificatePath", None)
    log = tempfile.TemporaryFile(mode="w+t")
    process = subprocess.Popen(
        ["dotnet", "run", "--no-build", "-c", "Release", "--project", "pat-lab/PatLab.csproj"],
        env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(120):
        if process.poll() is not None:
            log.seek(0)
            raise RuntimeError(f"host {port} exited: " + log.read()[-3000:])
        try:
            status, body, _ = req(port, "GET", "/operator/ping")
            if status == 200 and body.get("ready"): return process, log
        except (OSError, TimeoutError): pass
        time.sleep(0.5)
    raise RuntimeError(f"host {port} startup timeout")

def stop(handle):
    if handle is None: return
    process, log = handle
    process.terminate()
    try: process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    log.close()

def new_token(port, cookie, name):
    return req(port, "POST", "/api/atlas/tokens",
               {"name": name, "allowWrite": True, "expiresInDays": 365},
               cookie=cookie, csrf=True)

def cert_file(directory):
    key, crt, pem = [os.path.join(directory, "inert." + suffix)
                     for suffix in ("key", "crt", "pem")]
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=inert-lab", "-keyout", key, "-out", crt],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    with open(pem, "w", encoding="utf-8") as dest:
        for source in (crt, key):
            with open(source, encoding="utf-8") as part: dest.write(part.read())
    return pem

def main():
    issuer = prep = old = retiring = fresh = None
    with tempfile.TemporaryDirectory() as temp:
        cert = cert_file(temp)
        try:
            issuer = start(5291)
            status, _, cookie = req(5291, "POST", "/operator/issue")
            assert status == 200 and cookie and cookie.startswith("__Host-ContactsApi.Auth=")
            _, initial, _ = req(5291, "GET", "/operator/repository")
            assert initial["count"] == 1
            old_id = initial["keyIds"][0]
            stop(issuer); issuer = None
            prep = start(5291, cert)
            created, _, _ = req(5291, "POST", "/operator/create-key")
            _, two_keys, _ = req(5291, "GET", "/operator/repository")
            assert created == 200 and two_keys["count"] == 2
            stop(prep); prep = None
            old = start(5291, cert)
            denied_anon, _, _ = new_token(5291, None, "anon")
            denied_no_csrf, _, _ = req(5291, "POST", "/api/atlas/tokens",
                {"name": "no-csrf", "allowWrite": True}, cookie=cookie)
            denied_bad_origin, _, _ = req(5291, "POST", "/api/atlas/tokens",
                {"name": "bad-origin", "allowWrite": True}, cookie=cookie,
                csrf=True, origin="https://other.example.invalid")
            baseline_status, baseline, _ = new_token(5291, cookie, "baseline")
            assert baseline_status == 200, (baseline_status, baseline)
            baseline_token = baseline["data"]["token"]
            baseline_id = baseline["data"]["info"]["id"]
            baseline_check, baseline_result, _ = req(5291, "GET", "/operator/check-pat", bearer=baseline_token)
            baseline_revoke, _, _ = req(5291, "DELETE", "/api/atlas/tokens/" + baseline_id,
                                        cookie=cookie, csrf=True)
            _, revoked_result, _ = req(5291, "GET", "/operator/check-pat", bearer=baseline_token)
            # The retiring warm process is port 5291. A separate process revokes A
            # only after that process has entered its protected-value scan.
            retiring = start(5292, cert)
            begin_status, begin, _ = req(5291, "POST", "/operator/begin-retire")
            assert begin_status == 200 and not begin["retirementCompleted"]
            assert not begin["cacheCanceled"]
            remote_status, _, _ = req(5292, "POST", "/operator/revoke-key", {"keyId": old_id})
            assert remote_status == 200
            pre_delete_status, pre_delete, _ = new_token(5291, cookie, "after-remote-revoke")
            assert pre_delete_status == 200, (pre_delete_status, pre_delete)
            pre_delete_id = pre_delete["data"]["info"]["id"]
            pre_delete_revoke, _, _ = req(5291, "DELETE", "/api/atlas/tokens/" + pre_delete_id,
                                          cookie=cookie, csrf=True)
            finish_status, finish, _ = req(5291, "POST", "/operator/finish-retire")
            assert finish_status == 200 and finish["keysRetired"] == 1
            assert finish["refused"] is None and finish["retireBlocked"] is None
            assert not finish["cacheCanceled"] and old_id not in finish["keyIds"]
            post_status, post, _ = new_token(5291, cookie, "after-retire")
            assert post_status == 200, (post_status, post)
            post_token, post_id = post["data"]["token"], post["data"]["info"]["id"]
            foreign_cookie_status, _, _ = new_token(5292, cookie, "foreign-denied")
            invalidation_status, invalidation, _ = req(5291, "POST", "/operator/invalidate-local")
            after_invalidation_status, _, _ = new_token(5291, cookie, "local-invalidation-denied")
            print(json.dumps({
                "runtime": "10.0.15", "same_deleting_process": True,
                "anonymous_status": denied_anon, "no_csrf_status": denied_no_csrf,
                "bad_origin_status": denied_bad_origin, "baseline_mint_status": baseline_status,
                "baseline_bearer_write": baseline_check == 200 and baseline_result["canWrite"],
                "baseline_revoke_status": baseline_revoke,
                "revoked_bearer_denied": not revoked_result["accepted"],
                "remote_revoke_status": remote_status,
                "pre_delete_mint_status": pre_delete_status,
                "pre_delete_revoke_status": pre_delete_revoke,
                "retire_status": finish_status, "old_xml_absent": old_id not in finish["keyIds"],
                "cache_canceled_by_retire": finish["cacheCanceled"],
                "post_delete_mint_status": post_status,
                "post_delete_token_write": post["data"]["info"]["canWrite"],
                "foreign_process_old_cookie_status": foreign_cookie_status,
                "invalidation_status": invalidation_status,
                "local_cache_canceled": invalidation["cacheCanceled"],
                "after_local_invalidation_status": after_invalidation_status,
            }), flush=True)
            stop(old); old = None
            stop(retiring); retiring = None
            fresh = start(5291, cert)
            old_cookie_status, _, _ = new_token(5291, cookie, "fresh-denied")
            bearer_status, bearer_result, _ = req(5291, "GET", "/operator/check-pat", bearer=post_token)
            new_issue, _, new_cookie = req(5291, "POST", "/operator/issue")
            fresh_revoke, _, _ = req(5291, "DELETE", "/api/atlas/tokens/" + post_id,
                                     cookie=new_cookie, csrf=True)
            _, final_result, _ = req(5291, "GET", "/operator/check-pat", bearer=post_token)
            print(json.dumps({
                "fresh_old_cookie_status": old_cookie_status,
                "fresh_bearer_accepted": bearer_status == 200 and bearer_result["accepted"],
                "fresh_bearer_write": bearer_result["canWrite"],
                "fresh_owner_issue_status": new_issue,
                "fresh_owner_revoke_status": fresh_revoke,
                "final_bearer_denied": not final_result["accepted"],
            }), flush=True)
        finally:
            for handle in (fresh, retiring, old, prep, issuer): stop(handle)

if __name__ == "__main__": main
