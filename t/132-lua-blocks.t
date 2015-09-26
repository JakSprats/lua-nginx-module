# vim:set ft= ts=4 sw=4 et fdm=marker:
use lib 'lib';
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_on();
#workers(2);
#log_level('warn');

repeat_each(2);
#repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 2);

#no_diff();
no_long_string();
run_tests();

__DATA__

=== TEST 1: content_by_lua_block (simplest)
--- config
    location = /t {
        content_by_lua_block {
            ngx.say("hello, world")
        }
    }
--- request
GET /t
--- response_body
hello, world
--- no_error_log
[error]



=== TEST 2: content_by_lua_block (nested curly braces)
--- config
    location = /t {
        content_by_lua_block {
            local a = {
                dogs = {32, 78, 96},
                cat = "kitty",
            }
            ngx.say("a.dogs[1] = ", a.dogs[1])
            ngx.say("a.dogs[2] = ", a.dogs[2])
            ngx.say("a.dogs[3] = ", a.dogs[3])
            ngx.say("a.cat = ", a.cat)
        }
    }
--- request
GET /t
--- response_body
a.dogs[1] = 32
a.dogs[2] = 78
a.dogs[3] = 96
a.cat = kitty

--- no_error_log
[error]



=== TEST 3: content_by_lua_block (curly braces in strings)
--- config
    location = /t {
        content_by_lua_block {
            ngx.say("}1, 2)")
            ngx.say('{1, 2)')
        }
    }
--- request
GET /t
--- response_body
}1, 2)
{1, 2)

--- no_error_log
[error]



=== TEST 4: content_by_lua_block (curly braces in strings, with escaped terminators)
--- config
    location = /t {
        content_by_lua_block {
            ngx.say("\"}1, 2)")
            ngx.say('\'{1, 2)')
        }
    }
--- request
GET /t
--- response_body
"}1, 2)
'{1, 2)

--- no_error_log
[error]



=== TEST 5: content_by_lua_block (curly braces in long brackets)
--- config
    location = /t {
        content_by_lua_block {
            --[[
                {{{

                        }
            ]]
            --[==[
                }}}

                        {
            ]==]
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 6: content_by_lua_block ("nested" long brackets)
--- config
    location = /t {
        content_by_lua_block {
            --[[
                ]=]
            '  "
                        }
            ]]
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 7: content_by_lua_block (curly braces in line comments)
--- config
    location = /t {
        content_by_lua_block {
            --}} {}
            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]



=== TEST 8: content_by_lua_block (cosockets)
--- config
    server_tokens off;
    location = /t {
        content_by_lua_block {
            local sock = ngx.socket.tcp()
            local port = ngx.var.port
            local ok, err = sock:connect('127.0.0.1', tonumber(ngx.var.server_port))
            if not ok then
                ngx.say("failed to connect: ", err)
                return
            end

            ngx.say('connected: ', ok)

            local req = "GET /foo HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            -- req = "OK"

            local bytes, err = sock:send(req)
            if not bytes then
                ngx.say("failed to send request: ", err)
                return
            end

            ngx.say("request sent: ", bytes)

            while true do
                local line, err, part = sock:receive()
                if line then
                    ngx.say("received: ", line)

                else
                    ngx.say("failed to receive a line: ", err, " [", part, "]")
                    break
                end
            end

            ok, err = sock:close()
            ngx.say("close: ", ok, " ", err)
        }
    }

    location /foo {
        content_by_lua_block { ngx.say("foo") }
        more_clear_headers Date;
    }

--- request
GET /t
--- response_body
connected: 1
request sent: 57
received: HTTP/1.1 200 OK
received: Server: nginx
received: Content-Type: text/plain
received: Content-Length: 4
received: Connection: close
received: 
received: foo
failed to receive a line: closed []
close: 1 nil
--- no_error_log
[error]



=== TEST 9: all in one
--- http_config
    init_by_lua_block {
        glob = "init by lua }here{"
    }

    init_worker_by_lua_block {
        glob = glob .. ", init worker }here{"
    }
--- config
    location = /t {
        set $a '';
        rewrite_by_lua_block {
            local s = ngx.var.a
            s = s .. "}rewrite{\n"
            ngx.var.a = s
        }
        access_by_lua_block {
            local s = ngx.var.a
            s = s .. '}access{\n'
            ngx.var.a = s
        }
        content_by_lua_block {
            local s = ngx.var.a
            s = s .. [[}content{]]
            ngx.say(s)
            ngx.say("glob: ", glob)
        }
        log_by_lua_block {
            print("log by lua running \"}{!\"")
        }
        header_filter_by_lua_block {
            ngx.header["Foo"] = "\"Hello, world\""
            ngx.header["Content-Length"] = nil
        }
        body_filter_by_lua_block {
            local data, eof = ngx.arg[1], ngx.arg[2]
            print("eof = ", eof)
            if eof then
                if not data then
                    data = ""
                end
                data = data .. "}body filter{\n"
                print("data: ", data)
                ngx.arg[1] = data
            end
        }
    }
--- request
GET /t
--- response_body
}rewrite{
}access{
}content{
glob: init by lua }here{, init worker }here{
}body filter{

--- response_headers
Foo: "Hello, world"
--- error_log
log by lua running "}{!"
--- no_error_log
[error]



=== TEST 10: missing ]] (string)
--- config
    location = /t {
        content_by_lua_block {
            ngx.say([[hello, world")
        }
    }
--- request
GET /t
--- response_body
hello, world
--- no_error_log
[error]
--- must_die
--- error_log eval
qr/\[emerg\] .*? Lua code block missing the closing long bracket in .*?\bnginx\.conf:40/



=== TEST 11: missing ]] (comment)
--- config
    location = /t {
        content_by_lua_block {
            ngx.say(--[[hello, world")
        }
    }
--- request
GET /t
--- response_body
hello, world
--- no_error_log
[error]
--- must_die
--- error_log eval
qr/\[emerg\] .*? Lua code block missing the closing long bracket in .*?\bnginx\.conf:40/



=== TEST 12: missing }
FIXME: we need better diagnostics by actually loading the inlined Lua code while parsing
the *_by_lua_block directive.

--- config
    location = /t {
        content_by_lua_block {
            ngx.say("hello")
--- request
GET /t
--- response_body
hello, world
--- no_error_log
[error]
--- error_log
"events" directive is not allowed here
--- must_die



=== TEST 13: content_by_lua_block (compact)
--- config
    location = /t {
        content_by_lua_block {ngx.say("hello, world", {"!"})}
    }
--- request
GET /t
--- response_body
hello, world!
--- no_error_log
[error]



=== TEST 14: content_by_lua_block (unexpected closing long brackets)
--- config
    location = /t {
        content_by_lua_block {
            ]=]
        }
    }
--- request
GET /t
--- no_error_log
[error]
--- error_log eval
qr{\[emerg\] .*? unexpected lua closing long-bracket in .*?/nginx\.conf:40}
--- must_die