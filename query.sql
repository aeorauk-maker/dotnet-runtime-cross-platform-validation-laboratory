\set ON_ERROR_STOP on
select table_name, column_name from information_schema.columns where table_schema = 'ordering' and table_name in ('orders', 'buyers', 'IntegrationEventLog', 'requests') and column_name in ('Id', 'BuyerId', 'IdentityGuid', 'PaymentMethodId', 'OrderStatus', 'EventTypeName', 'State', 'Content') order by table_name, ordinal_position;
select 'order', "Id", "BuyerId", "OrderStatus" from ordering.orders order by "Id";
select 'buyer', "Id", "IdentityGuid", "Name" from ordering.buyers order by "Id";
select 'order_buyer_payment', o."Id", b."IdentityGuid", o."PaymentMethodId", p."PaymentToken"
  from ordering.orders o join ordering.buyers b on b."Id" = o."BuyerId"
  left join ordering.paymentmethods p on p."Id" = o."PaymentMethodId" order by o."Id";
select 'payment', p."Id", b."IdentityGuid", p."PaymentToken"
  from ordering.paymentmethods p join ordering.buyers b on b."Id" = p."BuyerId" order by p."Id";
select 'event_count', "EventTypeName", "State", count(*) from ordering."IntegrationEventLog" group by "EventTypeName", "State" order by "EventTypeName", "State";
select 'requests', count(*) from ordering.requests;
