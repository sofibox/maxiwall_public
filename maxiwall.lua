-- Author: Arafat Ali
-- Email: webmaster@sofibox.com
-- Website: https://www.sofibox.com
-- Version: 1.0
-- Description: This Suricata script, equipped with IPS capabilities, is designed to parse alerts and block the specified target.
-- It requires the maxiwall command line tool for optimal functionality and has been tested on Suricata 6.0.9
-- To install maxiwall use maxibuild at https://github.com/sofibox/maxibuild_public.git

-- suricata log level
function echo(msg, level)
    suricata_enable_scan = to_boolean(exec_read_line("maxiwall getenv SURICATA_ENABLE_LOG"))
    if suricata_enable_scan == true then
        level = level or "info"

        local log_functions = {
            err = SCLogError,
            warn = SCLogWarning,
            notice = SCLogNotice,
            info = SCLogInfo,
            debug = SCLogDebug
        }

        local log_function = log_functions[level]
        if log_function then
            log_function(msg)
        end
    end
end

-- This is a popen wrapper function used to handle and destroy file handler for read line output command
function exec_read_line(cmd)
    local handle = io.popen(cmd)
    local result = handle:read("*line")
    handle:close()
    return result
end

-- This is a popen wrapper function used to handle and destroy file handler for read all output command
function exec_read_all(cmd)
    local handle = io.popen(cmd)
    local result = handle:read("*all")
    handle:close()
    return result
end

-- This is a popen wrapper function used to handle and destroy file handler (no output to return)
function exec(cmd)
    local handle = io.popen(cmd)
    handle:close()
end

-- This function is used to sleep the script for specified duration in seconds
function sleep(duration)
    local finish = os.time() + duration
    repeat
    until os.time() >= finish
end

-- This function convert string "false" or "true" to boolean. This is useful because data received from wrapper is pure string
function to_boolean(str)
    return str == "true" or str == "1" or str == "yes"
end

-- This function convert any string including nil and empty string to number. Empty and nil string will become 0
function to_number(str)
    return tonumber(str) or 0
end

-- Exit report (Note does not seems to stop the report as it will continue to run)
function exit(code)
    os.exit(code)
end

function csf_block(ip, comment)
    local get_csf_block_status
    echo("START CSF BLOCK")
    echo ("Blocking " .. ip .. " with comment " .. comment .. "")

    if to_boolean(exec_read_line("maxiwall getenv SURICATA_ENABLE_CSF_BLOCK")) == true then
        -- This is the command to block IP
        get_csf_block_status = tostring(exec_read_line("maxiwall block-ip --ip-address='" .. ip .. "' --comment'" .. comment .. "'"))
        if get_csf_block_status == "error-no-dns-record" then
            echo("CSF block failed, no DNS record found for " .. ip)
        elseif get_csf_block_status == "ip-already-blocked" then
            echo("CSF block failed, " .. ip .. " is already blocked")
        elseif get_csf_block_status == "ok-ip-block-success" then
            echo("CSF block success, " .. ip .. " is blocked")
        else
            echo("error-ip-block-failed")
        end
    else
        echo("Warning, CSF block is disabled!")
    end
    echo("END CSF BLOCK")
end


-- This is an initialization function required by Suricata to specify which data needs to be displayed.
-- We are particularly interested in packets that generate alerts.
function init ()
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
end

-- This is the function that is called when the fast.lua is setup
function setup ()
    -- This variable holds the report count
    report_count = 0
    -- This variable holds the local IP address of a suspected IP in log report
    suspected_ip = ""
    -- The report file is the file where the alert.log is written
    report_file = assert(io.open(tostring(exec_read_line("maxiwall output-path") .. "/maxiwall.log"), "a"))
    -- This variable holds the local IPv4 address
    local_ipv4 = tostring(exec_read_line("maxiwall get-public-ipv4 --scripting"))
    -- This variable holds the local IPv6 address
    local_ipv6 = tostring(exec_read_line("maxiwall get-public-ipv6 --scripting"))
end

-- This is the function that is called when a new fast.log is created
function log()
    local sleep_duration
    local time_string, rule_sid, rule_rev, rule_gid, ip_version, src_ip, dst_ip, protocol, src_port, dst_port, msg, class, priority, suricata_alert_level
    local mod_security_scan_result, aipdb_scan_result, blcheck_scan_result, csf_scan_result, greynoise_scan_result, virustotal_scan_result
    local alert_categories, ip_score_label, alert_label
    local csf_block_comment

    -- Sleep for specified duration in seconds
    sleep_duration = to_number(exec_read_line("maxiwall getenv MAXIWALL_OUTPUT_SLEEP_RATE"))

    if sleep_duration > 0 then
        echo("Sleeping for " .. sleep_duration .. " seconds", "info")
        sleep(sleep_duration)
    end

    -- Obtain the timestring value from suricata function
    time_string = SCPacketTimeString()
    -- Obtain the rule signature ID, rule revision and rule group ID from suricata function
    rule_sid, rule_rev, rule_gid = SCRuleIds()
    -- Obtain the ip version, source IP, destination IP, IP protocol, source port and destination port from suricata function
    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCPacketTuple()
    -- Obtain the rule triggered message from suricata function (this value normally contain series of words)
    msg = SCRuleMsg()
    -- Obtain the rule class and rule priority from suricata function
    class, priority = SCRuleClass()

    -- Make sure the suricata record alert has proper datatype
    time_string = tostring(time_string)
    rule_sid = tonumber(rule_sid)
    rule_rev = tonumber(rule_rev)
    rule_gid = tonumber(rule_gid)
    ip_version = tostring(ip_version)
    src_ip = tostring(src_ip)
    dst_ip = tostring(dst_ip)
    protocol = tostring(protocol)
    src_port = tostring(src_port)
    dst_port = tostring(dst_port)
    msg = tostring(msg)
    class = tostring(class)
    priority = tonumber(priority)

    -- Sometimes triggered rule does not have rule class, if so assign class to unknown string to display in alert report
    if class == "" then
        class = "unknown"
    end

    -- If the source IP is local IP then assign LOCAL_IPV4 or LOCAL_IPV6 string to source IP
    if src_ip == local_ipv4 then
        src_ip = "LOCAL_IPV4"
        suspected_ip = tostring(dst_ip)
    elseif src_ip == local_ipv6 then
        src_ip = "LOCAL_IPV6"
        suspected_ip = tostring(dst_ip)
    end

    -- If the destination IP is local IP then assign LOCAL_IPV4 or LOCAL_IPV6 string to destination IP
    if dst_ip == local_ipv4 then
        dst_ip = "LOCAL_IPV4"
        suspected_ip = tostring(src_ip)
    elseif dst_ip == local_ipv6 then
        dst_ip = "LOCAL_IPV6"
        suspected_ip = tostring(src_ip)
    end

    -- Define suricata priority alert_level_label
    if priority == 1 then
        suricata_alert_level = "Very High Risk"
    elseif priority == 2 then
        suricata_alert_level = "High Risk"
    elseif priority == 3 then
        suricata_alert_level = "Medium Risk"
    elseif priority > 3 then
        suricata_alert_level = "Low Risk"
    else
        suricata_alert_level = "Unknown Risk"
    end

    if string.match(class, "web application") then
        -- Web App Attack
        alert_categories = "21"
    elseif string.match(class, "user") or string.match(class, "User") or string.match(class, "administrator") or string.match(class, "Administrator") then
        -- Bruteforce
        alert_categories = "18"
    elseif string.match(class, "suspicious username") or string.match(class, "default username") then
        -- Bruteforce, SSH
        alert_categories = "18,22"
    elseif (string.match(class, "rpc") or string.match(class, "Network scan") or
            string.match(class, "Information Leak") or string.match(class, "ETN AGGRESSIVE")) then
        -- Port scan
        alert_categories = "14"
    elseif string.match(class, "Denial of Service") then
        -- DDOS Attack
        alert_categories = "4"

    else
        -- If not above just use the default category, Hacking.
        alert_categories = "15"

    end

    if string.match(SCRuleMsg(), "SQL INJECTION") then
        -- Above category + SQL Injection category
        alert_categories = alert_categories .. ",16"
    end

    -- DEBUG
    -- This IP has bad aipdb reputation 100%
    -- suspected_ip = "76.65.114.5"
    -- This IP inside csf.deny
    -- suspected_ip="62.138.2.243"
    -- This IP inside csf.deny with network group attack
    -- suspected_ip="1.2.3.6"



    -- Run aipdb scan here
    if to_boolean(exec_read_line("maxiwall getenv ABUSEIPDB_ENABLE_SCAN")) == true then
        -- This is the command to run aipdb scan
        aipdb_scan_result = tostring(exec_read_line("maxiwall aipdb-scan --ip-address=" .. suspected_ip .. " --scripting"))
        echo("AbuseIPDB Scan Result: " .. tostring(aipdb_scan_result))
    end

    -- Run blcheck scan here -- TODO this is disabled for now
    if to_boolean(exec_read_line("maxiwall getenv BLCHECK_ENABLE_SCAN")) == true then
        -- This is the command to run blcheck scan
        blcheck_scan_result = tostring(exec_read_line("maxiwall blcheck-scan --ip-address=" .. suspected_ip .. " --scripting"))
        -- TODO The value of blcheck_scan_result is what we interested here
        echo("BLCheck Scan Result: " .. tostring(blcheck_scan_result))
    end

    -- run greynoise scan here
    if to_boolean(exec_read_line("maxiwall getenv GREYNOISE_ENABLE_SCAN")) == true then
        -- This is the command to run greynoise scan
        greynoise_scan_result = tostring(exec_read_line("maxiwall greynoise-scan --ip-address=" .. suspected_ip .. " --scripting"))
        -- TODO The value of greynoise_scan_result is what we interested here
        echo("GreyNoise Scan Result: " .. tostring(greynoise_scan_result))

    end

    -- run virustotal scan here
    if to_boolean(exec_read_line("maxiwall getenv VIRUSTOTAL_ENABLE_SCAN")) == true then
        -- This is the command to run virustotal scan
        virustotal_scan_result = tostring(exec_read_line("maxiwall virustotal-scan --ip-address=" .. suspected_ip .. " --scripting"))
        -- TODO The value of virustotal_scan_result is what we interested here
        echo("VirusTotal Scan Result: " .. tostring(virustotal_scan_result))
    end

    -- run csf_cidr_scan scan here
    if to_boolean(exec_read_line("maxiwall getenv CSF_ENABLE_CIDR_SCAN")) == true then
        -- This is the command to run csf_cidr_scan scan
        csf_cidr_scan_result = tostring(exec_read_line("maxiwall csf-cidr-scan --ip-address=" .. suspected_ip .. " --netmask=24 --input-file=/etc/csf/csf.deny --scripting"))
        -- TODO The value of csf_cidr_scan_result is what we interested here
        echo("CSF CIDR Scan Result: " .. tostring(csf_cidr_scan_result))
    end


    -- Check if IP is in csf.deny
    if to_boolean(exec_read_line("maxiwall getenv CSF_ENABLE_SCAN")) == true then
        -- This is the command to run aipdb scan
        csf_scan_result = tostring(exec_read_line("maxiwall csf-scan --ip-address=" .. suspected_ip .. " --scripting"))
        -- TODO The value of csf_scan_result is what we interested here
        echo("CSF Scan Result: " .. tostring(csf_scan_result))
    end

    -- Check if IP is in modsecurity log file
    if to_boolean(exec_read_line("maxiwall getenv MODSECURITY_ENABLE_SCAN")) == true then
        -- This is the command to run modsecurity scan
        mod_security_scan_result = tostring(exec_read_line("maxiwall modsecurity-scan --ip-address=" .. suspected_ip .. " --scripting"))
        -- TODO The value of mod_security_scan_result is what we interested here
        echo("ModSecurity Scan Result: " .. tostring(mod_security_scan_result))
    end

    -- Check if IP is in DABFM log file (TODO) - This is temporary disabled in config file -- going to implement using dacli API
    if to_boolean(exec_read_line("maxiwall getenv DABFM_ENABLE_SCAN")) == true then
        -- This is the command to run DABFM scan
        dabfm_scan_result = tostring(exec_read_line("maxiwall dabfm-scan --ip-address=" .. suspected_ip .. " --scripting"))
        -- TODO The value of dabfm_scan_result is what we interested here
        echo("DABFM Scan Result: " .. tostring(dabfm_scan_result))
    end


    -- Populate blocking ip_score_label (give aipdb_scan highest priority)
    if to_number(aipdb_scan_result) >= 80 then
        ip_score_label = "bad"

        csf_block_comment = "Blocked by Suricata->AbuseIPDB_score: " .. aipdb_scan_result .. ""

        if (to_number(aipdb_scan_result) == 100) then
            csf_block_comment = tostring(csf_block_comment) .. " # do not delete"
        end
        -- This is the command to block IP
        csf_block(suspected_ip, csf_block_comment)

    end

    if (priority == 1) or (priority == 2) then
        ip_score_label = "bad"
        if csf_block_comment == nil then
            csf_block_comment = "Blocked by Suricata->Alert_Level: " .. suricata_alert_level .. " "
        else
            csf_block_comment = tostring(csf_block_comment) .. " # | Suricata->Priority_number: " .. suricata_alert_level .. " "
        end

    end

    if greynoise_scan_result == "malicious" then
        ip_score_label = "bad"
        if csf_block_comment == nil then
            csf_block_comment = "Blocked by Suricata->GreyNoise_scan: " .. greynoise_scan_result .. " "
        else
            csf_block_comment = tostring(csf_block_comment) .. " | Greynoise: " .. greynoise_scan_result .. " "
        end

    end

    if virustotal_scan_result == "malicious" then
        ip_score_label = "bad"
        if csf_block_comment == nil then
            csf_block_comment = "Blocked by Suricata->VirusTotal_scan: " .. virustotal_scan_result .. " "
        else
            csf_block_comment = tostring(csf_block_comment) .. " | Virustotal: " .. virustotal_scan_result .. " "
        end
    end

    if mod_security_scan_result == "found" then
        ip_score_label = "bad"
        if csf_block_comment == nil then
            csf_block_comment = "Blocked by Suricata->ModSecurity_scan: " .. mod_security_scan_result .. " "
        else
            csf_block_comment = tostring(csf_block_comment) .. " | ModSecurity: " .. mod_security_scan_result .. " "
        end
    end

    if ip_score_label == "bad" then
        -- This is the command to block IP
        csf_block(suspected_ip, csf_block_comment)
    end
    echo("This is suricata alert IP information:")
    echo("---------------------START------------------------")
    echo("Suspected IP: " .. suspected_ip)
    echo("Time: " .. time_string, "debug")
    echo("Rule SID: " .. tostring(rule_sid))
    echo("Rule Rev: " .. tostring(rule_rev))
    echo("Rule GID: " .. tostring(rule_gid))
    echo("IP Version: " .. ip_version)
    echo("Source IP: " .. src_ip)
    echo("Destination IP: " .. dst_ip)
    echo("Protocol: " .. protocol)
    echo("Source Port: " .. src_port)
    echo("Destination Port: " .. dst_port)
    echo("Message: " .. msg)
    echo("Class: " .. class)
    echo("Priority: " .. tostring(priority))
    echo("Alert Level: " .. suricata_alert_level)
    echo("----------------------END-------------------------")


    -- local json = require("dkjson")
    -- Write json into alert.log using dkjson library
    --local t = {}
    --t["time"] = time_string
    --t["rule_sid"] = rule_sid
    --t["rule_rev"] = rule_rev
    --t["rule_gid"] = rule_gid
    --t["ip_version"] = ip_version
    --t["src_ip"] = src_ip
    --t["dst_ip"] = dst_ip
    --t["protocol"] = protocol
    --t["src_port"] = src_port
    --t["dst_port"] = dst_port
    --t["msg"] = msg
    --t["class"] = class
    --t["priority"] = priority
    --local s = json.encode(t, { indent = true })
    --report_file:write(s)
    --report_file:flush()

    report_count = report_count + 1
    -- Print the alert.log report count
    echo("END OF ALERT LOG REPORT #" .. tostring(alert_log_count))
end

-- This is the function that is called when the fast.lua is closed
function deinit ()
    echo("Alerted " .. report_count .. " times");
    report_file:close()
end

