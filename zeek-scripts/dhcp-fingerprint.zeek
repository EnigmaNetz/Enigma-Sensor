@load base/protocols/dhcp

module DHCP;

# Adds param_req_list column to dhcp.log. Values are populated by the Go
# processor via gopacket after Zeek runs, because this Zeek build does not
# expose DHCP::Options$param_req_list at script level.
redef record Info += {
    param_req_list: string &optional &log;
};
