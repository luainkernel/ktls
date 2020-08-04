buf = ''

-- recv hook, m is message
function recv(path, m)
    local code = 0
    local file = ''
    buf = buf..m
    if (string.sub(buf, -4) == '\r\n\r\n')
    then
        local method = string.match(buf, "%S+")
        local name = string.match(buf, "%S+", string.len(method) + 2)
        code = 200
        file = path..name
        buf = ''
    end
    return code, file
end

print('In entry')
