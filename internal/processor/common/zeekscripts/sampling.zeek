@load base/protocols/conn
@load base/protocols/dns

module Sampling;

export {
    ## The sampling percentage (0-100). Default is 100 (no sampling).
    ## Can be overridden via command line: zeek -r file.pcap sampling_percentage=50 ./sampling.zeek
    const sampling_percentage = 100.0 &redef;
}

# Counter for debugging
global total_connections = 0;
global sampled_connections = 0;
global total_dns_queries = 0;
global sampled_dns_queries = 0;

# Simple sampling at the logging level
hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
    {
    ++total_connections;

    # Always log if 100% sampling
    if ( sampling_percentage >= 100.0 )
        {
        ++sampled_connections;
        return;
        }

    # Never log if 0% sampling
    if ( sampling_percentage <= 0.0 )
        {
        break;
        }

    # Random sampling
    local random_val = rand(10000) / 100.0;
    if ( random_val >= sampling_percentage )
        {
        # Don't log this connection
        break;
        }
    else
        {
        ++sampled_connections;
        }
    }

hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
    {
    ++total_dns_queries;

    # For DNS, we'll use the same random approach
    if ( sampling_percentage >= 100.0 )
        {
        ++sampled_dns_queries;
        return;
        }

    if ( sampling_percentage <= 0.0 )
        {
        break;
        }

    local random_val = rand(10000) / 100.0;
    if ( random_val >= sampling_percentage )
        {
        break;
        }
    else
        {
        ++sampled_dns_queries;
        }
    }

event zeek_init()
    {
    if ( sampling_percentage < 100.0 )
        Reporter::info(fmt("Traffic sampling enabled at %.1f%%", sampling_percentage));
    }

event zeek_done()
    {
    if ( sampling_percentage < 100.0 )
        {
        Reporter::info(fmt("Sampled %d out of %d connections (%.1f%%)",
                          sampled_connections, total_connections,
                          total_connections > 0 ? sampled_connections * 100.0 / total_connections : 0.0));
        if ( total_dns_queries > 0 )
            Reporter::info(fmt("Sampled %d out of %d DNS queries (%.1f%%)",
                              sampled_dns_queries, total_dns_queries,
                              sampled_dns_queries * 100.0 / total_dns_queries));
        }
    }