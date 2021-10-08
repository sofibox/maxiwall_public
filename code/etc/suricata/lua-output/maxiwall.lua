-- Author: Arafat Ali
-- This is suricata custom report that has IPS capability
-- This report will use maxiwall wrapper

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

-- This is an OS specific function useful to sleep suricata statement in this script. Similar to sleep(n) in bash
function sleep(duration)
    os.execute("sleep " .. tonumber(duration))
end

-- This function convert string "false" or "true" to boolean. This is useful because data received from wrapper is pure string
function to_boolean(str)
    return str == "true" or str == "1" or str == "yes"
end

-- This function convert any string including nil and empty string to number. Empty and nil string will become 0
function to_number(str)
    str = tonumber(str)
    if type(str) == "nil" then
        return 0
    else
        return str
    end
end

-- This might be useless because this report will never exit unless suricata is stopped (just leave this here)
function exit()
    os.exit()
end
-- This function is used whether to display log
function logNotice(log_msg)
    -- This will display this script log in suricata.log
    if is_suricata_enable_script_log == true then
        log_pattern = "[Maxiwall.lua]: " .. log_msg
        SCLogNotice(log_pattern)
    end

    -- This is a independent script debug log file (that does not depend on the suricata.log)
    if is_maxiwall_enable_script_log == true then
        log_pattern = "[Maxiwall.lua]: " .. log_msg
        script_log_open:write(log_pattern .. "\n")
        script_log_open:flush()
    end
end

function csf_block(ip, comment)
    local get_csf_block_status
    logNotice("=== START csf_block() ===")

    get_csf_block_status = tostring(exec_read_line("maxiwall cmd block-target '" .. ip .. "' " .. comment))

    if get_csf_block_status == "error-no-dns-record" then
        logNotice("Error, could not resolve given IP or target")
        csf_block_status_label_description = "Error, could not resolve IP"
        csf_alert_action = "No suggestion due to error found when blocking target"
    elseif get_csf_block_status == "error-ip-block-failed" then
        logNotice("Error, CSF IP blocked failed")
        csf_block_status_label_description = "Error, CSF IP block failed"
        csf_alert_action = "No suggestion due to error found when blocking target"
    elseif get_csf_block_status == "ip-already-blocked" then
        logNotice("This IP was previously blocked by CSF")
        csf_block_status_label_description = "This IP was previously blocked by CSF"
        csf_alert_action = "No suggestion because CSF has blocked this IP before"
    else
        csf_block_status_label_description = tostring(get_csf_block_status)
        csf_alert_action = "No suggestion due to unknown status"
    end

    csf_block_status = tostring(get_csf_block_status)

    logNotice("csf_block_status_label_description: " .. tostring(csf_block_status_label_description) .. " | type: " .. type(csf_block_status_label_description))
    logNotice("csf_alert_action: " .. tostring(csf_alert_action) .. " | type: " .. type(csf_alert_action))

    logNotice("=== END csf_block() ===")
end

function send_alert()

end

-- This function sends email report, email must be set in maxiwall.conf
-- TODO test this
function send_mail(mail_content, mail_subject)

    -- Writing the mail content into file
    mail_report_log_open:write(mail_content)
    mail_report_log_open:flush()

    -- Send email (only if is_maxiwall_enable_mail_report is true)
    if is_maxiwall_enable_mail_report == true then
        logNotice("Global mail report is enabled.")

        -- This will send a lot of email if the downtime is long. So use this only for debugging
        -- disable enable_api_error_mail when in production

        logNotice("Notice, is_maxiwall_enable_mail_error_report is enabled. Sending log to email " .. maxiwall_report_email)

        cmdstr = "mail -s '" .. mail_subject .. "' '" .. maxiwall_report_email .. "' < " .. maxiwall_mail_report_log_path
        exec(cmdstr)
        logNotice("Clearing the mail report log file " .. maxiwall_mail_report_log_path)
        io.open(maxiwall_mail_report_log_path, "w"):close()

    else
        logNotice("Warning, global mail report is disabled. No email will be sent")
    end

end

function aipdb_scan(ip)
    local aipdb_get_ip_cache_status, aipdb_get_new_ip_cache_status

    logNotice("=== START aipdb_scan() ===")
    -- First make sure that the IP we want to cache does not exist in the cache file.
    -- Use wrapper: maxiwall cmd aipdb-get-ip-cache-status <ip> to check this

    aipdb_get_ip_cache_status = to_boolean(exec_read_line("maxiwall cmd 'aipdb-get-ip-cache-status' '" .. ip .. "'"))
    -- If an IP does not exist in cache, then we cache it
    if aipdb_get_ip_cache_status == false then
        logNotice("Warning, the IP " .. ip .. " is not cached")
        logNotice("Now caching IP " .. ip .. " info from AIPDB ... ")
        aipdb_get_new_ip_cache_status = tostring(exec_read_line("maxiwall cmd 'aipdb-get-ip-info' '" .. ip .. "'"))
        -- Set it as a new IP label for the first time
        aipdb_ip_cache_status = tostring(aipdb_get_new_ip_cache_status)
        aipdb_cache_label_status = "new"
    else
        logNotice("[Skipped]: The IP " .. ip .. " is already cached!")
        aipdb_ip_cache_status = "notice-ip-already-cache"
        -- Set it as an old IP label because the cached found inside the cache file.
        aipdb_cache_label_status = "cached"
    end

    -- This is extra label for aipdb cache based on value aipdb_cache_label_status

    if aipdb_cache_label_status == "new" then
        aipdb_cache_label_status_description = "New IP Info"
    else
        aipdb_cache_label_status_description = "Cached IP Info"
    end

    logNotice("The global AIPDB IP cache status is: " .. tostring(aipdb_ip_cache_status))

    -- This function here is used to detect whether cache is success, if not success we restart the log
    if aipdb_get_new_ip_cache_status == "error-no-dns-record" or aipdb_get_new_ip_cache_status == "warning-could-write-cache-ip" or aipdb_get_new_ip_cache_status == "error-api-check-is-down" or aipdb_get_new_ip_cache_status == "warning-curl-has-error" or aipdb_get_new_ip_cache_status == "warning-api-has-error" then

        logNotice("[AIPDB] Warning, Problem when caching IP address " .. ip .. " from AIPDB: " .. aipdb_ip_cache_status)

        if is_maxiwall_enable_mail_error_report == true then
            send_mail("[Maxiwall.lua]: Warning, Maxiwall has detected issue when caching IP address " .. ip .. " from AIPDB: \n"
                    .. "Short error details: " .. aipdb_get_new_ip_cache_status .. "\n"
                    .. "Run the maxiwall wrapper script with verbose mode (-v) eg: maxiwall cmd -v write-aipdb-cache " .. ip .. " to get full error details why it is failed when caching this IP" .. "\n", "[Maxiwall.lua | Warning]: [AIPDB] Problem when caching IP address " .. ip .. " @ " .. hostname)
        else
            logNotice("Warning, is_maxiwall_enable_mail_error_report is disabled. No email is sent, please read the log instead")
        end

        logNotice("Sleeping 30 seconds ...")
        sleep(30)
    end

    -- Then after the above condition, we read the IP cache information and assign each into variable.
    -- Usage: maxiwall cmd aipdb-get-cache-variable <ip> <variable_field>
    -- Example: maxiwall cmd aipdb-get-cache-variable 1.1.1.153 abuse_score, this will return abuse_score value
    logNotice("Assigning all variables from AIPDB cache file ...")
    aipdb_ip = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'ip'"))
    aipdb_target = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'target'"))
    aipdb_time = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'time'"))
    aipdb_is_whitelisted = to_boolean(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'is_whitelisted'"))
    aipdb_abuse_score = to_number(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'abuse_score'"))
    aipdb_isp = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'isp'"))
    aipdb_usage_type = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'usage_type'"))
    aipdb_domain = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'domain'"))
    aipdb_country_name = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'country_name'"))
    aipdb_country_code = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'country_code'"))
    aipdb_total_report = to_number(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'total_report'"))
    aipdb_distinct_report = to_number(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'distinct_report'"))
    aipdb_last_report = tostring(exec_read_line("maxiwall cmd aipdb-get-cache-variable '" .. ip .. "' 'last_report'"))

    -- Debug variable
    logNotice("This is a(n) " .. aipdb_cache_label_status .. " ip information:")
    logNotice("---------------------START------------------------")
    logNotice("aipdb_cache_label_status_description: " .. tostring(aipdb_cache_label_status_description) .. " | type: " .. type(aipdb_cache_label_status_description))
    logNotice("aipdb_ip: " .. tostring(aipdb_ip) .. " | type: " .. type(aipdb_ip))
    logNotice("aipdb_target: " .. tostring(aipdb_ip) .. " | type: " .. type(aipdb_target))
    logNotice("aipdb_time: " .. tostring(aipdb_time) .. " | type: " .. type(aipdb_time))
    logNotice("aipdb_is_whitelisted: " .. tostring(aipdb_is_whitelisted) .. " | type: " .. type(aipdb_is_whitelisted))
    logNotice("aipdb_abuse_score: " .. tostring(aipdb_abuse_score) .. " | type: " .. type(aipdb_abuse_score))
    logNotice("aipdb_isp: " .. tostring(aipdb_isp) .. " | type: " .. type(aipdb_isp))
    logNotice("aipdb_usage_type: " .. tostring(aipdb_usage_type) .. " | type: " .. type(aipdb_usage_type))
    logNotice("aipdb_domain: " .. tostring(aipdb_domain) .. " | type: " .. type(aipdb_domain))
    logNotice("aipdb_country_name: " .. tostring(aipdb_country_name) .. " | type: " .. type(aipdb_country_name))
    logNotice("aipdb_country_code: " .. tostring(aipdb_country_code) .. " | type: " .. type(aipdb_country_code))
    logNotice("aipdb_total_report: " .. tostring(aipdb_total_report) .. " | type: " .. type(aipdb_total_report))
    logNotice("aipdb_distinct_report: " .. tostring(aipdb_distinct_report) .. " | type: " .. type(aipdb_distinct_report))
    logNotice("aipdb_last_report: " .. tostring(aipdb_last_report) .. " | type: " .. type(aipdb_last_report))
    logNotice("----------------------END-------------------------")
    logNotice("=== END aipdb_scan() ===")
end

function aipdb_web_report(ip, category, comment)

end

-- this will be used as final judgement
function validate_ip_score(ip)

end

function blcheck_scan(ip)
    local blcheck_get_blacklist_status, blcheck_get_new_blacklist_count

    logNotice("=== START blcheck_scan() ====")

    logNotice("Checking existing IP " .. ip .. " in blacklisted file ...")

    blcheck_get_blacklist_status = to_boolean(exec_read_line("maxiwall cmd 'blcheck-get-ip-cache-status' '" .. ip .. "'"))

    logNotice("get_ip_blacklist_status is " .. tostring(blcheck_get_blacklist_status))

    if blcheck_get_blacklist_status == false then
        logNotice("IP is not in blacklisted file. Scanning IP " .. ip .. " for new blacklist data ...")
        -- Meaning if the IP does not exist in blacklist database (not blacklisted),
        -- We can run the blacklist scanner at the background (Temporarily not using background)
        -- cmdstr = "nohup bash maxiwall cmd blcheck " .. ip .. "  </dev/null >/dev/null 2>&1 &

        -- This will scan IP (default using cache output, silent, 75% CPU and output in blcheck dir)
        blcheck_get_new_blacklist_count = tostring(exec_read_line("maxiwall cmd blcheck '" .. ip .. "'"))
        -- Error handling (TODO test this email error)
        if blcheck_get_new_blacklist_count == "error-blcheck-not-installed" or blcheck_get_new_blacklist_count == "error-invalid-action" then
            logNotice("Warning, there is an error when checking blacklist IP")

            if is_maxiwall_enable_mail_error_report == true then
                send_mail("Warning, there is an error when checking for blacklisted IP: \n"
                        .. "Error details: " .. ip_blacklisted_count, "[Maxiwall.lua | Warning]: [BLCHECK] Problem when checking for blacklisted IP " .. ip .. " @ " .. hostname)
            else
                logNotice("Warning, is_maxiwall_enable_mail_error_report is disabled. No email is sent, please read the log instead")
            end

            logNotice("Sleeping 30 seconds ...")
            sleep(30)
        end

        blcheck_cache_label_status = "new"
    else
        logNotice("IP is already in blcheck blacklisted cached file")
        blcheck_cache_label_status = "cached"
    end

    -- Will return nil if already scan
    logNotice("New blacklist IP scan result is: " .. tostring(blcheck_get_new_blacklist_count))

    blcheck_tested_count = to_number(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'tested'"))
    blcheck_passed_count = to_number(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'passed'"))
    blcheck_allowed_count = to_number(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'allowed'"))
    blcheck_invalid_count = to_number(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'invalid'"))
    blcheck_blacklisted_count = to_number(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'blacklisted'"))
    blcheck_reputation_score = to_number(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'reputation'"))
    blcheck_bl_domain = tostring(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'bl_domain'"))
    -- this will only display unix timestamp
    blcheck_date_check = tostring(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'time'"))
    blcheck_comment = tostring(exec_read_line("maxiwall cmd blcheck-get-ip-variable '" .. ip .. "' 'comment'"))

    -- Debug variable
    logNotice("This is a(n) " .. blcheck_cache_label_status .. " ip information:")
    logNotice("---------------------START------------------------")
    logNotice("blcheck_tested_count: " .. tostring(blcheck_tested_count) .. " | type: " .. type(blcheck_tested_count))
    logNotice("blcheck_passed_count: " .. tostring(blcheck_passed_count) .. " | type: " .. type(blcheck_passed_count))
    logNotice("blcheck_allowed_count: " .. tostring(blcheck_allowed_count) .. " | type: " .. type(blcheck_allowed_count))
    logNotice("blcheck_invalid_count: " .. tostring(blcheck_invalid_count) .. " | type: " .. type(blcheck_invalid_count))
    logNotice("blcheck_blacklisted_count: " .. tostring(blcheck_blacklisted_count) .. " | type: " .. type(blcheck_blacklisted_count))
    logNotice("blcheck_reputation_score: " .. tostring(blcheck_reputation_score) .. " | type: " .. type(blcheck_reputation_score))
    logNotice("blcheck_bl_domain: " .. tostring(blcheck_bl_domain) .. " | type: " .. type(blcheck_bl_domain))
    logNotice("blcheck_date_check: " .. tostring(blcheck_date_check) .. " | type: " .. type(blcheck_date_check))
    logNotice("blcheck_comment: " .. tostring(blcheck_comment) .. " | type: " .. type(blcheck_comment))
    logNotice("----------------------END-------------------------")
    logNotice("=== END blcheck_scan() ====")
end

function csf_cidr_24_scan(ip)

    get_ip2cidr24 = tostring(exec_read_line("maxiwall cmd get-ip2cidr24 '" .. ip .. "'"))
    logNotice("get_ip2cidr24: " .. tostring(get_ip2cidr24))

    csf_count_ip2cidr24 = to_number(exec_read_line("maxiwall cmd csf-count-ip2cidr24 '" .. ip .. "'"))
    logNotice("count_ip2cidr24: " .. tostring(csf_count_ip2cidr24))

    if (csf_count_ip2cidr24 == 0) then
        csf_ip2cidr24_message = "Notice, IP has no group record in CSF permanent deny list"
        csf_ip2cidr24_action = "No suggestion for this"
        csf_ip2cidr24_group_label = "has no record"
    elseif (tonumber(csf_count_ip2cidr24) == 1) then
        csf_ip2cidr24_message = "Notice, there is 1 network IP x.x.x.0/24 in csf.deny that might belong to this IP"
        csf_ip2cidr24_action = "No action for this"
        csf_ip2cidr24_group_label = "single"
    elseif (tonumber(csf_count_ip2cidr24) >= 1) and (tonumber(csf_count_ip2cidr24) < 5) then
        csf_ip2cidr24_message = "Notice, found " .. csf_count_ip2cidr24 .. " network IPs x.x.x.0/24 in csf.deny that might belong to this IP"
        csf_ip2cidr24_action = "No action for this"
        csf_ip2cidr24_group_label = "network"
    elseif (tonumber(csf_count_ip2cidr24) >= 5) then
        csf_ip2cidr24_message = "Warning, found " .. csf_count_ip2cidr24 .. "  network IPs x.x.x.0/24 in csf.deny. This IP might belong to a large group of suspicious network"
        -- TODO Enable auto CIDR block here instead of suggestion
        csf_ip2cidr24_action = "It is recommend that to block this IP in CIDR form " .. get_ip2cidr24 .. " to increase CSF performance"
        csf_ip2cidr24_group_label = "network"
    else
        csf_count_ip2cidr24 = "0" -- set the default value for cidr count if ipv6
        csf_ip2cidr24_message = "No message for this due to unknown data"
        csf_ip2cidr24_action = "No action for this due to unknown data"
        csf_ip2cidr24_group_label = "No group label due to unknown data"
    end

    -- Debug variable
    logNotice("=== START csf_cidr_24_scan() ===")
    logNotice("---------------------START------------------------")
    logNotice("csf_count_ip2cidr24: " .. tostring(csf_count_ip2cidr24) .. " | type: " .. type(csf_count_ip2cidr24))
    logNotice("get_ip2cidr24: " .. tostring(get_ip2cidr24) .. " | type: " .. type(get_ip2cidr24))
    logNotice("csf_ip2cidr24_message: " .. tostring(csf_ip2cidr24_message) .. " | type: " .. type(csf_ip2cidr24_message))
    logNotice("csf_ip2cidr24_action: " .. tostring(csf_ip2cidr24_action) .. " | type: " .. type(csf_ip2cidr24_action))
    logNotice("----------------------END-------------------------")
    logNotice("=== END csf_cidr_24_scan() ===")
end

-- TODO also get the suspicious log count here (this also get the mod security log status)
function maxiwall_log_scan(ip)
    local get_maxiwall_log_scan_status

    logNotice("=== START maxiwall_log_scan ===")
    -- This function will look for an IP for suspected log found in system, if found, it will then write a report for that IP for each log path,
    -- It also will categorize each log for reporting
    -- usage: maxiwall cmd scanlog <ip>
    get_maxiwall_log_scan_status = tostring(exec_read_line("maxiwall cmd 'scan-log' '" .. ip .. "'"))

    if get_maxiwall_log_scan_status == "error-ip-not-valid" or get_maxiwall_log_scan_status == "error-no-suspicious-log-found" then
        if is_maxiwall_enable_mail_error_report == true then
            send_mail("Warning, there is an error when checking IP for suspicious log: \n"
                    .. "Error details: " .. get_maxiwall_log_scan_status, "[Maxiwall.lua | Warning]: [Maxiwall Log Scanner] Problem when checking for suspicious log for IP " .. ip .. " @ " .. hostname)
        else
            logNotice("Warning, is_maxiwall_enable_mail_error_report is disabled. No email is sent, please read the log instead")
        end
    end


    -- maxiwall cmd maxiwall-search-ip-log-variable <ip> <field>

    -- This global variable is used to show status of the scanned log
    maxiwall_log_scan_status = tostring(get_maxiwall_log_scan_status)
    maxiwall_log_suspicious_count = tonumber(exec_read_line("maxiwall cmd 'maxiwall-search-ip-log-variable' '" .. ip .. "' 'suspicious_count'"))
    maxiwall_log_suspicious_score = tonumber(exec_read_line("maxiwall cmd 'maxiwall-search-ip-log-variable' '" .. ip .. "' 'suspicious_score'"))
    maxiwall_log_mod_security_alert = to_boolean(exec_read_line("maxiwall cmd 'maxiwall-search-ip-log-variable' '" .. ip .. "' 'mod_security_alert'"))
    maxiwall_log_attack_category = tostring(exec_read_line("maxiwall cmd 'maxiwall-search-ip-log-variable' '" .. ip .. "' 'attack_category'"))
    if maxiwall_log_attack_category == "no-record" then
        maxiwall_log_attack_category = "0"
    end
    maxiwall_log_comment = tostring(exec_read_line("maxiwall cmd 'maxiwall-search-ip-log-variable' '" .. ip .. "' 'comment'"))


    -- Debug variable

    logNotice("---------------------START------------------------")
    logNotice("maxiwall_log_scan_status: " .. tostring(maxiwall_log_scan_status) .. " | type: " .. type(maxiwall_log_scan_status))
    logNotice("maxiwall_log_suspicious_count: " .. tostring(maxiwall_log_suspicious_count) .. " | type: " .. type(maxiwall_log_suspicious_count))
    logNotice("maxiwall_log_suspicious_score: " .. tostring(maxiwall_log_suspicious_score) .. " | type: " .. type(maxiwall_log_suspicious_score))
    logNotice("maxiwall_log_mod_security_alert: " .. tostring(maxiwall_log_mod_security_alert) .. " | type: " .. type(maxiwall_log_mod_security_alert))
    logNotice("maxiwall_log_attack_category: " .. tostring(maxiwall_log_attack_category) .. " | type: " .. type(maxiwall_log_attack_category))
    logNotice("maxiwall_log_comment: " .. tostring(maxiwall_log_comment) .. " | type: " .. type(maxiwall_log_comment))
    logNotice("----------------------END-------------------------")

    logNotice("==== END maxiwall_log_scan====")

end

-- This is an init function that is requires by Suricata to define what data need to display
-- We are interested with packet with alerts
function init ()
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
end

-- This is the setup function where we declare and assign all variables to be used for suricata to process the report
function setup ()

    maxiwall_score_label = ""
    -- Get enable whitelist IP setting
    is_maxiwall_enable_whitelist_ip = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-whitelist-ip"))

    -- Get enable ignore IP setting
    is_maxiwall_enable_ignore_ip = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-ignore-ip"))

    -- Get enable suppress IP setting
    is_maxiwall_enable_suppress_ip = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-suppress-ip"))

    -- Get enable suppress message setting
    is_maxiwall_enable_suppress_msg = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-suppress-msg"))

    -- Get enable auto action (automatically take action based on rules)
    is_maxiwall_enable_auto_action = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-auto-action"))

    -- This will enable or disable mail report log
    is_maxiwall_enable_mail_report = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-mail-report"))

    -- This is used to sleep alert log, so we reduce the log read write overhead
    -- Suricata might have this function enabled but we can control this in script for delay
    maxiwall_ip_alert_sleep_duration = to_number(exec_read_line("maxiwall cmd get-maxiwall-ip-alert-sleep-duration"))

    -- This will set the maximum limit to send alert report rate
    maxiwall_limit_email_alert_report_rate = to_number(exec_read_line("maxiwall cmd get-maxiwall-limit-email-alert-report-rate"))

    -- This will set the maximum limit to send error report rate
    maxiwall_limit_email_error_report_rate = to_number(exec_read_line("maxiwall cmd get-maxiwall-limit-email-error-report-rate"))

    -- This will set the maximum limit to write in maxiwall alert log

    maxiwall_lua_alert_max_count = to_number(exec_read_line("maxiwall cmd  get-maxiwall-lua-alert-max-count"))



    -- This will enable or disable API error mail report
    is_maxiwall_enable_mail_error_report = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-mail-error-report"))


    -- This will enable or disable script log
    is_maxiwall_enable_script_log = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-script-log"))

    -- This will enable or disable script log report in suricata.log
    is_suricata_enable_script_log = to_boolean(exec_read_line("maxiwall cmd get-suricata-enable-script-log"))

    -- Get the hostname
    hostname = tostring(exec_read_line("maxiwall cmd get-hostname"))

    -- This is the email from maxiwall.conf that is used to send report
    maxiwall_report_email = tostring(exec_read_line("maxiwall cmd get-maxiwall-report-email"))

    -- This will get the public IPv4 for the current host (this will use api.ipify.org from maxiwall)
    local_ipv4 = tostring(exec_read_line("maxiwall cmd get-local-ipv4"))

    -- This will get the public IPv6 for the current host (this will use api64.ipify.org from maxiwall)
    local_ipv6 = tostring(exec_read_line("maxiwall cmd get-local-ipv6"))

    -- All maxiwall log rule related variables
    is_maxiwall_enable_log_rule = to_boolean(exec_read_line("maxiwall cmd get-maxiwall-enable-log-rule"))

    maxiwall_log_scan_status = ""
    maxiwall_log_suspicious_count = ""
    maxiwall_log_suspicious_score = ""
    maxiwall_log_mod_security_alert = ""
    maxiwall_log_attack_category = ""
    maxiwall_log_comment = ""

    -- All suricata rule related variables
    suricata_alert_level_label = ""

    -- All CSF IP CIDR24 global variables

    -- Enable CSF CIDR IPv4 blocking rule
    is_csf_enable_ipv4_cidr_24_network_block = to_boolean(exec_read_line("maxiwall cmd get-csf-enable-ipv4-cidr-24-network-block"))

    csf_count_ip2cidr24 = ""
    get_ip2cidr24 = ""
    csf_ip2cidr24_message = ""
    csf_ip2cidr24_action = ""
    is_csf_enable_auto_block = to_boolean(exec_read_line("maxiwall cmd get-csf-enable-auto-block"))

    -- ALL CSF global variables
    csf_block_status_label_description = ""
    csf_alert_action = ""
    csf_block_status = ""
    -- All AIPDB global variables

    is_aipdb_enable_rule = to_boolean(exec_read_line("maxiwall cmd get-aipdb-enable-rule"))

    aipdb_ip = ""
    aipdb_target = ""
    aipdb_time = ""
    aipdb_is_whitelisted = ""
    aipdb_abuse_score = ""
    aipdb_isp = ""
    aipdb_usage_type = ""
    aipdb_domain = ""
    aipdb_country_name = ""
    aipdb_country_code = ""
    aipdb_total_report = ""
    aipdb_distinct_report = ""
    aipdb_last_report = ""
    -- This is a label to determine whether the AIPDB IP cache status (old/cached or new)
    aipdb_cache_label_status = ""
    -- This is the more descriptive label from the variable aipdb_cache_label_status (human readable)
    aipdb_cache_label_status_description = ""
    -- This status is obtained when doing IP cache for aipdb
    aipdb_ip_cache_status = ""

    -- All blcheck global variable

    -- This will enable rblscan using blcheck
    is_blcheck_enable_rule = to_boolean(exec_read_line("maxiwall cmd get-blcheck-enable-rule"))

    blcheck_tested_count = ""
    blcheck_passed_count = ""
    blcheck_allowed_count = ""
    blcheck_invalid_count = ""
    blcheck_blacklisted_count = ""
    blcheck_reputation_score = ""
    blcheck_bl_domain = ""
    -- this will only display unix timestamp
    blcheck_date_check = ""
    blcheck_comment = ""
    blcheck_cache_label_status = ""


    -- This is a report count
    report_count = 0

    -- This variable hold the value of a suspected IP in log report
    suspected_ip = ""

    -- Files and logs

    -- The main Maxiwall lua log (For script debugging)
    maxiwall_script_log_name = tostring(exec_read_line("maxiwall cmd get-maxiwall-script-log-name"))
    maxiwall_script_log_name_path = SCLogPath() .. maxiwall_script_log_name
    script_log_open = assert(io.open(maxiwall_script_log_name_path, "a"))

    -- The main Maxiwall alert log (will show both critical and non critical alert)
    maxiwall_alert_log_name = tostring(exec_read_line("maxiwall cmd get-maxiwall-alert-log-name"))
    maxiwall_alert_log_name_path = SCLogPath() .. maxiwall_alert_log_name
    alert_log_open = assert(io.open(maxiwall_alert_log_name_path, "a"))

    -- The mail report log name used to send error or important log
    maxiwall_mail_report_log_name = tostring(exec_read_line("maxiwall cmd get-maxiwall-mail-report-log-name"))
    maxiwall_mail_report_log_path = SCLogPath() .. maxiwall_mail_report_log_name
    mail_report_log_open = assert(io.open(maxiwall_mail_report_log_path, "a"))
end

-- This function will be run multiple times by suricata to produce dynamic report
-- It obtains some variable from suricata function begin with SCFunctionName()
-- When declaring variable from suricata function, the variable name can be anything but must be in order of its existence
-- Always refer to documentation about suricata function: https://suricata.readthedocs.io/en/latest/lua/lua-functions.html
function log()

    local is_whitelisted_ip_status, is_ignored_ip_status

    -- This will print all maxiwall related variables
    logNotice("=== START maxiwall ====")
    -- This is an important sleep function that will reduce suricata alert scan duration
    if maxiwall_ip_alert_sleep_duration >= 0 then
        logNotice("Notice, maxiwall_ip_alert_sleep_duration is triggered to delay this script for " .. maxiwall_ip_alert_sleep_duration .. " seconds")
        sleep(maxiwall_ip_alert_sleep_duration)
    else
        logNotice("Notice, maxiwall_ip_alert_sleep_duration is disable. Log duration is realtime")
    end

    logNotice("is_csf_enable_ipv4_cidr_24_network_block " .. tostring(is_csf_enable_ipv4_cidr_24_network_block))
    logNotice("is_maxiwall_enable_whitelist_ip " .. tostring(is_maxiwall_enable_whitelist_ip))
    logNotice("is_maxiwall_enable_ignore_ip " .. tostring(is_maxiwall_enable_ignore_ip))
    logNotice("maxiwall_ip_alert_sleep_duration " .. tostring(maxiwall_ip_alert_sleep_duration))
    logNotice("is_maxiwall_enable_mail_report " .. tostring(is_maxiwall_enable_mail_report))
    logNotice("is_maxiwall_enable_mail_error_report " .. tostring(is_maxiwall_enable_mail_error_report))
    logNotice("is_maxiwall_enable_script_log " .. tostring(is_maxiwall_enable_script_log))
    logNotice("is_suricata_enable_script_log " .. tostring(is_suricata_enable_script_log))
    logNotice("hostname " .. tostring(hostname))
    logNotice("maxiwall_report_email " .. tostring(maxiwall_report_email))
    logNotice("local_ipv4 " .. tostring(local_ipv4))
    logNotice("local_ipv6 " .. tostring(local_ipv6))
    logNotice("maxiwall_script_log_name " .. tostring(maxiwall_script_log_name))
    logNotice("maxiwall_script_log_name_path " .. tostring(maxiwall_script_log_name_path))
    logNotice("maxiwall_alert_log_name " .. tostring(maxiwall_alert_log_name))
    logNotice("maxiwall_alert_log_name_path " .. tostring(maxiwall_alert_log_name_path))
    logNotice("maxiwall_mail_report_log_name " .. tostring(maxiwall_mail_report_log_name))
    logNotice("maxiwall_mail_report_log_path " .. tostring(maxiwall_mail_report_log_path))
    logNotice("is_maxiwall_enable_log_rule " .. tostring(is_maxiwall_enable_log_rule))
    logNotice("is_aipdb_enable_rule " .. tostring(is_aipdb_enable_rule))
    logNotice("is_blcheck_enable_rule " .. tostring(is_blcheck_enable_rule))
    logNotice("----------------------END-------------------------")
    logNotice("=== END maxiwall  ====")

    logNotice("=== START suricata data ====")

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

    -- If the source IP is a local IPv4, display it as LOCAL_IPV4 in alert report and assign the suspected IP as the destination IP
    if src_ip == local_ipv4 then
        src_ip = "LOCAL_IPV4"
        suspected_ip = tostring(dst_ip)
        -- else if the source IP is a local IPv6, display it as LOCAL_IPV6 in alert report and assign the suspected IP as the destination IP
    elseif src_ip == local_ipv6 then
        src_ip = "LOCAL_IPV6"
        suspected_ip = tostring(dst_ip)
    end

    -- If the destination IP is a local IPv4, display it as LOCAL_IPV4 in alert report and assign the suspected IP as the source IP
    if dst_ip == local_ipv4 then
        dst_ip = "LOCAL_IPV4"
        suspected_ip = tostring(src_ip)
        -- else if the destination IP is a local IPv6, display it as LOCAL_IPV6 in alert report and assign the suspected IP as the source IP
    elseif dst_ip == local_ipv6 then
        dst_ip = "LOCAL_IPV6"
        suspected_ip = tostring(src_ip)
    end

    -- Define suricata priority label
    if priority == 1 then
        suricata_alert_level_label = "Very High Risk"
    elseif priority == 2 then
        suricata_alert_level_label = "High Risk"
    elseif priority == 3 then
        suricata_alert_level_label = "Medium Risk"
    elseif priority > 3 then
        -- 4, 5, 7, 8, 9 above
        suricata_alert_level_label = "Low Risk"
    end

    -- Debug variable
    logNotice("This is a suricata alert ip information:")
    logNotice("---------------------START------------------------")
    logNotice("time_string: " .. tostring(time_string) .. " | type: " .. type(time_string))
    logNotice("rule_sid: " .. tostring(rule_sid) .. " | type: " .. type(rule_sid))
    logNotice("rule_rev: " .. tostring(rule_rev) .. " | type: " .. type(rule_rev))
    logNotice("rule_gid: " .. tostring(rule_gid) .. " | type: " .. type(rule_gid))
    logNotice("ip_version: " .. tostring(ip_version) .. " | type: " .. type(ip_version))
    logNotice("src_ip: " .. tostring(src_ip) .. " | type: " .. type(src_ip))
    logNotice("dst_ip: " .. tostring(dst_ip) .. " | type: " .. type(dst_ip))
    logNotice("protocol: " .. tostring(protocol) .. " | type: " .. type(protocol))
    logNotice("src_port: " .. tostring(src_port) .. " | type: " .. type(src_port))
    logNotice("dst_port: " .. tostring(dst_port) .. " | type: " .. type(dst_port))
    logNotice("msg: " .. tostring(msg) .. " | type: " .. type(msg))
    logNotice("class: " .. tostring(class) .. " | type: " .. type(class))
    logNotice("priority: " .. tostring(priority) .. " | type: " .. type(priority))
    logNotice("suspected_ip: " .. tostring(suspected_ip) .. " | type: " .. type(suspected_ip))
    logNotice("suricata_alert_level_label: " .. tostring(suricata_alert_level_label) .. " | type: " .. type(suricata_alert_level_label))
    logNotice("----------------------END-------------------------")
    logNotice("=== END suricata data ====")

    is_whitelisted_ip_status = to_boolean(exec_read_line("maxiwall cmd maxiwall-get-whitelisted-ip-status '" .. suspected_ip .. "'"))

    is_ignored_ip_status = to_boolean(exec_read_line("maxiwall cmd maxiwall-get-ignored-ip-status '" .. suspected_ip .. "'"))

    logNotice("IP is whitelisted?: " .. tostring(is_whitelisted_ip_status))

    logNotice("IP is ignored?: " .. tostring(is_ignored_ip_status))

    logNotice("IP_VERSION is: " .. ip_version)

    if (is_whitelisted_ip_status == true and is_maxiwall_enable_whitelist_ip == true) or (is_ignored_ip_status == true and is_maxiwall_enable_ignore_ip == true) then

        local whitelist_ignore_label = ""
        if is_whitelisted_ip_status == true then
            whitelist_ignore_label = "whitelist"
        elseif is_ignored_ip_status == true then
            whitelist_ignore_label = "ignore"
        end

        logNotice("Notice, IP : " .. suspected_ip .. " is in " .. whitelist_ignore_label .. " file. Ignoring this IP from reporting in Suricata")
    else

        -- Scan CIDR network 24 for CSF
        if is_csf_enable_ipv4_cidr_24_network_block == true and ip_version == "4" then
            logNotice("CSF IPv4 CIDR 24 block is enable")
            csf_cidr_24_scan(suspected_ip)

        else
            logNotice("Warning, CSF IPv4 CIDR 24 block is disabled")
        end

        -- Write AIPDB IP cache file for the suspected IP if is_aipdb_enable_rule is enabled
        if is_aipdb_enable_rule == true then
            aipdb_scan(suspected_ip)
        else
            logNotice("Warning, AIPDB rule is disabled")
        end

        -- Scan the selected IP for blacklist if is_blcheck_enable_rule is enabled
        if is_blcheck_enable_rule == true then
            blcheck_scan(suspected_ip)
        else
            logNotice("Warning, blcheck scanner rule is disabled")
        end

        if is_maxiwall_enable_log_rule == true then
            maxiwall_log_scan(suspected_ip)
        else
            logNotice("Warning, maxiwall log scanner rule is disabled")
        end

        -- Populate suricata attack category (also based on suspicious log scan)
        -- TODO I must always update this category based on the rule
        if string.match(class, "web application") then
            -- Web App Attack
            suricata_suspicious_category = "21"
        elseif string.match(class, "user") or string.match(class, "User") or string.match(class, "administrator") or string.match(class, "Administrator") then
            -- Bruteforce
            suricata_suspicious_category = "18"
        elseif string.match(class, "suspicious username") or string.match(class, "default username") then
            -- Bruteforce, SSH
            suricata_suspicious_category = "18,22"
        elseif (string.match(class, "rpc") or string.match(class, "Network scan") or string.match(class, "Information Leak")) then
            -- Port scan
            suricata_suspicious_category = "14"
        elseif string.match(class, "Denial of Service") then
            -- DDOS Attack
            suricata_suspicious_category = "4"
        elseif maxiwall_log_attack_category ~= "0" then
            -- Use category from the log suspicious from Maxiwall if it exist
            suricata_suspicious_category = maxiwall_log_attack_category
        else
            -- If not above just use the default category, Hacking.
            suricata_suspicious_category = "15"
        end

        if string.match(SCRuleMsg(), "SQL INJECTION") then
            -- Above category + SQL Injection category
            suricata_suspicious_category = suricata_suspicious_category .. ",16"
        end

        logNotice("Suricata attack_category is: " .. suricata_suspicious_category)


        -- Building report string template
        -- This is for both critical and non-critical log aka default log like fast.log
        str_report = "[N: " .. report_count .. " [PRIO: " .. priority .. " [TIME: " .. time_string ..
                " [SOURCE: " .. src_ip .. " [SP: " .. src_port .. " [TARGET: " .. dst_ip ..
                " [TP: " .. dst_port .. " [RG: " .. rule_gid .. " [RS: " .. rule_sid .. " [RR: " .. rule_rev ..
                " [CLASS: " .. class .. " [MSG: " .. '"' .. msg .. '"' .. "\n"

        -- Write the log into file
        alert_log_open:write(str_report)
        alert_log_open:flush()


        -- Get the source ip count Inbound
        maxiwall_src_ip_total_count = tonumber(exec_read_line("maxiwall cmd get-maxiwall-alert-source-ip-count '" .. suspected_ip .. "'"))
        -- Get the destination ip count Outbound
        maxiwall_dst_ip_total_count = tonumber(exec_read_line("maxiwall cmd get-maxiwall-alert-destination-ip-count '" .. suspected_ip .. "'"))

        -- Get both destination and source ip count (inbound and outbound)
        src_dst_total_count = tonumber(maxiwall_src_ip_total_count) + tonumber(maxiwall_dst_ip_total_count)

        logNotice("maxiwall_src_ip_total_count: " .. tostring(maxiwall_src_ip_total_count) .. " | type: " .. type(maxiwall_src_ip_total_count))
        logNotice("maxiwall_dst_ip_total_count: " .. tostring(maxiwall_dst_ip_total_count) .. " | type: " .. type(maxiwall_dst_ip_total_count))
        logNotice("src_dst_total_count: " .. tostring(src_dst_total_count) .. " | type: " .. type(src_dst_total_count))

        -- Populate the score for blocking

        -- Initialize label to unknown score
        maxiwall_score_label = "unknown"

        -- This is the first rule aipdb_abuse_score >=80 (only enable if is_aipdb_enable_rule is true
        if is_aipdb_enable_rule == true then
            if (tonumber(aipdb_abuse_score) >= 80) then
                maxiwall_score_label = "bad"
                -- Only block if auto block is enable
                logNotice("Notice, AIPDB abuse_score rule >=80 condition is matched")
                if is_csf_enable_auto_block == true then
                    logNotice("CSF auto block is enable. Blocking IP " .. suspected_ip .. " using CSF ...")
                    local block_comment = "Blocked by MAXIWALL.lua_AIPDB_aipdb_abuse_score [GeoIP: " .. aipdb_isp .. "/" .. aipdb_usage_type .. "/"
                            .. aipdb_domain .. "/" .. aipdb_country_code .. " [AIPDB_Abuse_Score:" .. aipdb_abuse_score
                            .. "% [Suricata_Alert_Level: " .. suricata_alert_level_label .. " [Inbound_Outbound: " .. src_dst_total_count .. " [Suricata_MSG: " .. msg
                    -- Tell CSF do not remove this IP even if it is reached limit
                    csf_block(suspected_ip, block_comment .. " #do not delete")
                    logNotice("CSF blocking status is: " .. csf_block_status)
                else
                    logNotice("CSF auto block is disabled but this IP has bad rule")
                    csf_block_status_label_description = "CSF auto block is not set but the bad rule has been triggered for this IP"
                    csf_alert_action = "No action for this because CSF auto block is not set but the bad rule has been triggered for this IP. You must take action!"

                end
            else
                logNotice("Notice, AIPDB abuse_score rule >=80 condition did not trigger")
            end
        else
            logNotice("Notice, AIPDB abuse_score rule >=80 condition did not trigger because is_aipdb_enable_rule is disabled ")
        end


        -- This is the second rule blacklist count must be >=5 and maxiwall_log_suspicious_count >=1
        if is_blcheck_enable_rule == true and is_maxiwall_enable_log_rule == true then
            if (tonumber(blcheck_blacklisted_count) >= 5 and tonumber(maxiwall_log_suspicious_count >= 1)) then
                maxiwall_score_label = "bad"
                logNotice("Notice, blcheck_blacklisted_count >=5 and maxiwall_log_suspicious_count >=1 condition is matched")
                if is_csf_enable_auto_block == true then
                    logNotice("CSF auto block is enable. Blocking IP " .. suspected_ip .. " using CSF ...")
                    local block_comment = "Blocked by MAXIWALL.lua_BLCHECK_blcheck&LOG_SCANNER_maxiwall_log_suspicious_count [Blcheck_Reputation_Score:" .. blcheck_reputation_score
                            .. " % [Maxiwall_Log_Suspicious_Score: " .. maxiwall_log_suspicious_score .. " % [Suricata_Alert_Level: " .. suricata_alert_level_label
                            .. " [Inbound_Outbound: " .. src_dst_total_count .. " [Suricata_MSG: " .. msg
                    csf_block(suspected_ip, block_comment)
                    logNotice("CSF blocking status is: " .. csf_block_status)
                else
                    logNotice("CSF auto block is disabled but this IP has bad rule")
                    csf_block_status_label_description = "CSF auto block is not set but the bad rule has been triggered for this IP"
                    csf_alert_action = "No action for this because CSF auto block is not set but the bad rule has been triggered for this IP. You must take action!"

                end

            else
                logNotice("Notice, blcheck_blacklisted_count >=5 and maxiwall_log_suspicious_count >=1 rules did not trigger")
            end
        else
            logNotice("Notice, blcheck_blacklisted_count >=5 and maxiwall_log_suspicious_count >=1 rules did not trigger because either one or both rules are disabled")
        end

        -- This is the third rule aipdb_abuse_score >=65 and blcheck_blacklisted_count >=2
        if is_aipdb_enable_rule == true and is_blcheck_enable_rule == true then

            if (tonumber(aipdb_abuse_score) >= 65 and tonumber(blcheck_blacklisted_count) >= 2) then
                maxiwall_score_label = "bad"
                logNotice("Notice, aipdb_abuse_score >=65 and blcheck_blacklisted_count >=2 condition is matched")
                if is_csf_enable_auto_block == true then
                    logNotice("CSF auto block is enable. Blocking IP " .. suspected_ip .. " using CSF ...")
                    local block_comment = "Blocked by MAXIWALL.lua_AIPDB_aipdb_abuse_score&BLCHECK_blcheck_blacklisted_count [GeoIP: " .. aipdb_isp .. "/" .. aipdb_usage_type .. "/"
                            .. aipdb_domain .. "/" .. aipdb_country_code .. " [AIPDB_Abuse_Score:" .. aipdb_abuse_score .. " % [Blcheck_Reputation_Score: " .. blcheck_reputation_score
                            .. " % [Suricata_Alert_Level: " .. suricata_alert_level_label
                            .. " [Inbound_Outbound: " .. src_dst_total_count .. " [Suricata_MSG: " .. msg
                    csf_block(suspected_ip, block_comment)
                    logNotice("CSF blocking status is: " .. csf_block_status)
                else
                    logNotice("CSF auto block is disabled but this IP has bad rule")
                    csf_block_status_label_description = "CSF auto block is not set but the bad rule has been triggered for this IP"
                    csf_alert_action = "No action for this because CSF auto block is not set but the bad rule has been triggered for this IP. You must take action!"

                end
            else
                logNotice("Notice, aipdb_abuse_score >=65 and blcheck_blacklisted_count >=2 rules did not trigger")
            end
        else
            logNotice("Notice, aipdb_abuse_score >=65 and blcheck_blacklisted_count >=2 rules did not trigger because either one or both rules are disabled")

        end

        -- This is the fourth rule suricata priority level either 1 (Very High Risk) or 2 (High Risk)

        if (tonumber(priority) == 1) or (tonumber(priority) == 2) then
            maxiwall_score_label = "bad"
            logNotice("Notice, suricata rule priority=1 or suricata rule priority=2 condition is matched")
            if is_csf_enable_auto_block == true then
                logNotice("CSF auto block is enable. Blocking IP " .. suspected_ip .. " using CSF ...")
                local block_comment = "Blocked by MAXIWALL.LUA_SURICATA_priority [Alert_Level: " .. suricata_alert_level_label .. " [Inbound_Outbound: " .. src_dst_total_count
                        .. " [Suricata_MSG: " .. msg
                csf_block(suspected_ip, block_comment)
                logNotice("CSF blocking status is: " .. csf_block_status)
            else
                logNotice("CSF auto block is disabled but this IP has bad rule")
                csf_block_status_label_description = "CSF auto block is not set but the bad rule has been triggered for this IP"
                csf_alert_action = "No action for this because CSF auto block is not set but the bad rule has been triggered for this IP. You must take action!"

            end
        else
            logNotice("Notice, suricata rule priority=1 or suricata rule priority=2 condition rules did not trigger")
        end

        -- This is the fifth rule check if mod_security_alert is triggered
        if is_maxiwall_enable_log_rule == true then

            if (to_boolean(mod_security_alert) == true) then
                maxiwall_score_label = "bad"
                logNotice("Notice, mod_security_alert=true condition is matched")
                if is_csf_enable_auto_block == true then
                    logNotice("CSF auto block is enable. Blocking IP " .. suspected_ip .. " using CSF ...")
                    local block_comment = "Blocked by MAXIWALL.LUA_LOG_SCANNER_mod_security_alert [Blcheck_Reputation_Score: " .. blcheck_reputation_score
                            .. " % [Mod_Security_Alert: " .. mod_security_alert .. " [Suricata_Alert_Level: " .. suricata_alert_level_label
                            .. " [Inbound_Outbound: " .. src_dst_total_count .. " [Suricata_MSG: " .. msg
                    csf_block(suspected_ip, block_comment)
                    logNotice("CSF blocking status is: " .. csf_block_status)
                else
                    logNotice("CSF auto block is disabled but this IP has bad rule")
                    csf_block_status_label_description = "CSF auto block is not set but the bad rule has been triggered for this IP"
                    csf_alert_action = "No action for this because CSF auto block is not set but the bad rule has been triggered for this IP. You must take action!"

                end
            else
                logNotice("Notice, mod_security_alert=true condition did not trigger")
            end
        else
            logNotice("Notice, mod_security_alert=true rule did not trigger because is_maxiwall_enable_log_rule is disabled ")
        end

        if is_csf_enable_auto_block == true then
            if csf_block_status == "ip-already-blocked" then
                maxiwall_score_label="bad"
            end
        end

        if maxiwall_score_label == "unknown" then
            logNotice("Notice, this IP did not trigger any blocking rule and has unknown bad score")
            -- This means this IP is in non-critical report
        end

        -- Increase report count to 1
        report_count = report_count + 1;
    end

    logNotice( "================== END OF LOG (" .. report_count .. ") =================\n\n")

end

-- This is the clean function
function deinit ()
    SCLogInfo("Alerted " .. report_count .. " times");
    io.close(script_log_open)
    io.close(alert_log_open)
    io.close(mail_report_log_open)
end