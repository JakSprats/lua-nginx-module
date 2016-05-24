
ngx.say('DEBUG SCRIPT RUNNING');

local pid = ngx.worker.pid();
local sip = ngx.var.server_addr;
ngx.say('SERVER: PID: ' .. pid .. ' IP: ' .. sip);


