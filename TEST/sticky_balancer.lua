local balancer     = require "ngx.balancer"

local sus = 'unix:/tmp/sticky_nginx_socket_' .. ngx.worker.pid();
ngx.log(ngx.INFO, "LOCAL_PATH: " .. sus);
local ok, err = balancer.set_current_peer(sus)
if not ok then
  ngx.log(ngx.ERR, "failed to set the current peer: ", err)
  return ngx.exit(500)
end
