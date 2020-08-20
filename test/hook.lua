buf = ''
wwwroot = './'
files = {}

-- recv hook, m is message
function recv(m)
    local code = 0
    local file = ''
    buf = buf..m
    if (string.sub(buf, -4) == '\r\n\r\n') then
        local name = buf:match('GET /(%S+) HTTP/%d%.%d\r\n')
        if files[name] then
            code = 200
            file = wwwroot..name
        else
            code = 500
        end
        buf = ''
    end
    return code, file
end

print('In entry')
