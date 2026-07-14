@load base/protocols/ssl
@load base/protocols/http

module JA3JA4Fingerprinting;

export {
    # Define a new log stream for JA3/JA4 fingerprints
    redef enum Log::ID += { JA3JA4_LOG };

    # Define the record that will contain our JA3/JA4 fingerprint information
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja3: string &log &optional;
        ja3_hash: string &log &optional;
        ja4: string &log &optional;
        ja4_hash: string &log &optional;
        client_version: string &log &optional;
        cipher_suites: vector of string &log &optional;
        extensions: vector of string &log &optional;
        server_name: string &log &optional;
        user_agent: string &log &optional;
    };

    # Global table to store JA3/JA4 fingerprints
    global ja3_ja4_fingerprints: table[string] of Info &read_expire=1day;

    # Add JA4S record type
    type JA4SInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja4s: string &log;
        ja4s_hash: string &log;
        server_version: string &log;
        server_cipher: string &log;
        server_extensions: vector of string &log;
        server_name: string &log;
    };

    # Add JA4S log stream
    redef enum Log::ID += { JA4S_LOG };

    # Global table to store server extensions
    global server_extensions: table[string] of vector of string;
}

# Function to calculate JA3 fingerprint
function calculate_ja3(c: connection, version: string, cipher_suites: vector of string, extensions: vector of string): string {
    local ja3 = fmt("%s,%s,%s",
        version,
        join_string_vec(cipher_suites, "-"),
        join_string_vec(extensions, "-"));
    return ja3;
}

# Function to calculate JA4 fingerprint
function calculate_ja4(c: connection, version: string, cipher_suites: vector of string, extensions: vector of string, user_agent: string &optional): string {
    # JA4 format: t{version}_{cipher_suites}_{extensions}_{user_agent_hash}
    local user_agent_hash = "0";
    if (user_agent != "") {
        user_agent_hash = md5_hash(user_agent);
    }
    local ja4 = fmt("t%s_%s_%s_%s",
        version,
        join_string_vec(cipher_suites, "-"),
        join_string_vec(extensions, "-"),
        user_agent_hash);
    return ja4;
}

# Function to calculate JA4S fingerprint
function calculate_ja4s(c: connection, version: string, cipher: string, extensions: vector of string): string {
    local ja4s = fmt("t%s_%s_%s",
        version,
        cipher,
        join_string_vec(extensions, "-"));
    return ja4s;
}

# Initialize the log stream
event zeek_init() {
    # Create the log stream with the correct parameters
    Log::create_stream(JA3JA4Fingerprinting::JA3JA4_LOG, [
        $columns=Info,
        $path="ja3_ja4"
    ]);

    # Initialize JA4S log
    Log::create_stream(JA4S_LOG, [$columns=JA4SInfo, $path="ja4s"]);
}

# Event handler for SSL/TLS Client Hello messages
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
    local info: Info;

    # Use existing info if available, otherwise create new
    if (c$uid in ja3_ja4_fingerprints) {
        info = ja3_ja4_fingerprints[c$uid];
    } else {
        info$ts = c$start_time;
        info$uid = c$uid;
        info$id = c$id;
    }

    info$client_version = fmt("%d", version);

    # Convert cipher suites to strings
    local cipher_suites: vector of string;
    for (idx in ciphers) {
        cipher_suites += fmt("%d", ciphers[idx]);
    }
    info$cipher_suites = cipher_suites;

    # Get extensions from SSL history and other SSL fields
    local extensions: vector of string;

    # Add server_name extension if SNI is present
    if (c$ssl?$server_name) {
        extensions += "0";  # server_name extension
        info$server_name = c$ssl$server_name;
    }

    # Add session_ticket extension if session was resumed
    if (c$ssl?$resumed && c$ssl$resumed) {
        extensions += "35";  # session_ticket extension
    }

    # Add supported_groups extension if curve is present
    if (c$ssl?$curve && c$ssl$curve != "") {
        extensions += "10";  # supported_groups extension
    }

    # Add signature_algorithms extension (common in TLS 1.3)
    if (version >= 0x0304) {  # TLS 1.3
        extensions += "13";  # signature_algorithms extension
    }

    # Add key_share extension (required for TLS 1.3)
    if (version >= 0x0304) {  # TLS 1.3
        extensions += "51";  # key_share extension
    }

    # Add supported_versions extension (required for TLS 1.3)
    if (version >= 0x0304) {  # TLS 1.3
        extensions += "43";  # supported_versions extension
    }

    # Add application_layer_protocol_negotiation extension if present
    if (c$ssl?$next_protocol && c$ssl$next_protocol != "") {
        extensions += "16";  # application_layer_protocol_negotiation extension
    }

    info$extensions = extensions;

    # Calculate JA3
    if (|cipher_suites| > 0 && |extensions| > 0) {
        info$ja3 = calculate_ja3(c, info$client_version, cipher_suites, extensions);
        info$ja3_hash = md5_hash(info$ja3);

        # Only write to log if this is a new connection
        if (!(c$uid in ja3_ja4_fingerprints)) {
            Log::write(JA3JA4Fingerprinting::JA3JA4_LOG, info);
        }
    }

    # Store the fingerprint information
    ja3_ja4_fingerprints[c$uid] = info;
}

# Event handler for HTTP User-Agent headers
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "USER-AGENT" && is_orig) {
        # Try to find the SSL connection that corresponds to this HTTP connection
        local matching_uid = "";
        local matching_fingerprint: Info;

        # First try to match by UID
        if (c$uid in ja3_ja4_fingerprints) {
            matching_uid = c$uid;
            matching_fingerprint = ja3_ja4_fingerprints[c$uid];
        }

        # If no match by UID, try to match by IP and port
        if (matching_uid == "") {
            for (uid, fingerprint in ja3_ja4_fingerprints) {
                if (fingerprint$id$orig_h == c$id$orig_h &&
                    fingerprint$id$orig_p == c$id$orig_p) {
                    matching_uid = uid;
                    matching_fingerprint = fingerprint;
                    break;
                }
            }
        }

        # If we found a match, update the fingerprint with the User-Agent
        if (matching_uid != "") {
            matching_fingerprint$user_agent = value;

            # Calculate JA4 if we have all required data
            if (matching_fingerprint?$client_version &&
                matching_fingerprint?$cipher_suites &&
                matching_fingerprint?$extensions) {

                matching_fingerprint$ja4 = calculate_ja4(
                    c,
                    matching_fingerprint$client_version,
                    matching_fingerprint$cipher_suites,
                    matching_fingerprint$extensions,
                    value
                );
                matching_fingerprint$ja4_hash = md5_hash(matching_fingerprint$ja4);

                # Update the stored fingerprint
                ja3_ja4_fingerprints[matching_uid] = matching_fingerprint;

                # Write to log
                Log::write(JA3JA4Fingerprinting::JA3JA4_LOG, matching_fingerprint);
            }
        }
    }
}

# Event handler for SSL/TLS Server Hello messages
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) {
    local info: JA4SInfo;
    info$ts = c$start_time;
    info$uid = c$uid;
    info$id = c$id;
    info$server_version = fmt("%d", version);
    info$server_cipher = fmt("%d", cipher);

    # Get server extensions if available
    if (c$uid in server_extensions) {
        info$server_extensions = server_extensions[c$uid];
    } else {
        info$server_extensions = vector();
    }

    # Get server name if available
    if (c$ssl?$server_name) {
        info$server_name = c$ssl$server_name;
    } else {
        info$server_name = "Unknown";
    }

    # Calculate JA4S
    info$ja4s = calculate_ja4s(c, info$server_version, info$server_cipher, info$server_extensions);
    info$ja4s_hash = md5_hash(info$ja4s);

    # Write to log
    Log::write(JA4S_LOG, info);
}

# Event handler for SSL/TLS extensions
event ssl_extension(c: connection, is_orig: bool, code: count, val: string) {
    if (!is_orig) {  # Server extensions
        if (c$uid in server_extensions) {
            server_extensions[c$uid] += fmt("%d", code);
        } else {
            server_extensions[c$uid] = vector(fmt("%d", code));
        }
    }
}
