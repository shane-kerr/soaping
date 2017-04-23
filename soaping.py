# TODO: figure out how to make initial log rotate name on the correct time
# TODO: get source IP address
import argparse
import base64
import errno
import json
import logging
import logging.handlers
import queue
import random
import re
import sys
import threading
import time

import dns.edns
import dns.message
import dns.query
import dns.rdatatype
import dns.rdtypes
import dns.resolver


def _auth_query_thread(target_id, target_ip, qname, qtype, resultq, stopev):
    logging.debug("_auth_query_thread(%r, %r, %r, %r, ...) startup",
                  target_id, target_ip, qname, qtype)
    # we will use the CLOCK_MONOTONIC_RAW if available,
    # otherwise CLOCK_MONOTONIC
    clock = getattr(time, 'CLOCK_MONOTONIC_RAW',
                    getattr(time, 'CLOCK_MONOTONIC'))
    nsid_option = dns.edns.GenericOption(dns.edns.NSID, b'')
    query = dns.message.make_query(qname, qtype, options=[nsid_option])
    while not stopev.is_set():
        try:
            query.id = random.randint(0, 65535)
            timestamp = time.time()
            time_a = time.clock_gettime(clock)
            answer = dns.query.udp(query, where=target_ip, timeout=1,
                                   ignore_unexpected=True)
            time_b = time.clock_gettime(clock)
            rt = time_b - time_a
            resultq.put((target_id, target_ip, query, timestamp, rt, answer))
            logging.debug("query -t %s %s @%s => %.4f seconds",
                          dns.rdatatype.to_text(qtype), qname,
                          target_ip, (time_b-time_a))
        except dns.exception.Timeout:
            logging.info("Timeout querying -t %s %s @%s",
                         dns.rdatatype.to_text(qtype), qname, target_ip)
        except OSError as ex:
            allowed_errors = (errno.ENETUNREACH, errno.ENETDOWN,
                              errno.EADDRNOTAVAIL)
            if ex.errno not in allowed_errors:
                logging.error("Unexpected OS error querying -t %s %s @%s: %s",
                              dns.rdatatype.to_text(qtype), qname,
                              target_ip, ex)

        except Exception as ex:
            logging.error("Unexpected %s exception querying -t %s %s @%s: %s",
                          type(ex), dns.rdatatype.to_text(qtype), qname,
                          target_ip, ex)

        sleep_time = random.normalvariate(1.0, 0.1)
        stopev.wait(timeout=sleep_time)

    logging.debug("_auth_query_thread(%r, %r, %r, %r, ...) shutdown",
                  target_id, target_ip, qname, qtype)


def _decode_rdata(name, ttl, rd):
    ans = {}
    if rd.rdtype == dns.rdatatype.SOA:
        ans["TYPE"] = "SOA"
        ans["NAME"] = name.to_text()
        ans["TTL"] = ttl
        ans["MNAME"] = rd.mname.to_text()
        ans["RNAME"] = rd.rname.to_text()
        ans["SERIAL"] = rd.serial
    elif rd.rdtype == dns.rdatatype.TXT:
        ans["TYPE"] = "TXT"
        ans["NAME"] = name.to_text()
        ans["TTL"] = ttl
        ans["RDATA"] = [s.decode() for s in rd.strings]
    return ans


# https://atlas.ripe.net/docs/data_struct/#v4610_dns
# missing:
#   from (added by backend)
#   group_id
#   lts (last time synchronized... could use -1)
#   msm_id (measurement ID)
#   msm_name (measurement name)
#   prb_id (probe ID)
def dnsresp2dict(proto, src_addr, dst_name, dst_addr,
                 error,
                 timestamp, rt,
                 query_msg, resp_msg):
    d = {}

    # pretend to be the latest firmware version
    d["fw"] = 4710

    answers = []
    if resp_msg.answer:
        for i in range(2):
            if i >= len(resp_msg.answer[0]):
                break
            ans = _decode_rdata(resp_msg.answer[0].name,
                                resp_msg.answer[0].ttl,
                                resp_msg.answer[0][i])
            if ans:
                answers.append(ans)

    result = {}
    result["ANCOUNT"] = len(resp_msg.answer)
    result["ARCOUNT"] = len(resp_msg.additional)
    result["ID"] = resp_msg.id
    result["NSCOUNT"] = len(resp_msg.authority)
    result["QCOUNT"] = len(resp_msg.question)
    result["abuf"] = base64.b64encode(resp_msg.to_wire()).decode()
    result["answers"] = answers
    result["rt"] = rt
    result["src_addr"] = src_addr
    d["result"] = result

    if ":" in dst_addr:
        d["af"] = 6
    else:
        d["af"] = 4
    if dst_name is not None:
        d["dns_name"] = dst_name
    d["dst_addr"] = dst_addr
    if error is not None:
        d["error"], d["timeout"], d["getaddrinfo"] = error
    # UDP or TCP
    d["proto"] = proto
    if query_msg:
        d["qbuf"] = base64.b64encode(query_msg.to_wire()).decode()
    d["timestamp"] = timestamp
    d["type"] = "dns"

    return d


def _json_log_namer(name):
    return re.sub(r'\.json', '', name) + ".json"


def _json_output_thread(resultq, interval):
    json_log = logging.getLogger('JSON output')
    json_log.propagate = False

    now = int(time.time())
    extra_rollover = now - (now % interval) + interval
    if interval % (24 * 60 * 60) == 0:
        when = 'D'
        interval //= 24 * 60 * 60
    elif interval % (60 * 60) == 0:
        when = 'H'
        interval //= 60 * 60
    elif interval % 60 == 0:
        when = 'M'
        interval //= 60
    else:
        when = 'S'
    rh = logging.handlers.TimedRotatingFileHandler("soaping.json",
                                                   when=when,
                                                   interval=interval,
                                                   utc=True)
    rh.namer = _json_log_namer
    json_log.addHandler(rh)
    json_log.setLevel(logging.INFO)

    while True:
        result = resultq.get()
        if result is None:
            break
        _, target_ip, query, timestamp, rt, answer = result
        d = dnsresp2dict(proto="UDP",
                         src_addr="192.0.2.1",
                         dst_name=None, dst_addr=target_ip,
                         error=None,
                         timestamp=timestamp, rt=rt*1000,
                         query_msg=query, resp_msg=answer)

        if extra_rollover and time.time() >= extra_rollover:
            rh.doRollover()
            extra_rollover = None
        json_log.info(json.dumps(d, sys.stdout))


def lookup_name_server_ips(domain):
    resolver = dns.resolver.Resolver()
    try:
        answer = resolver.query(domain, dns.rdatatype.NS)
    except Exception as ex:
        logging.error("Unexpected %s exception for NS lookup of %s: %s",
                      type(ex), domain, ex)
        return None

    ips = []
    for name_server in answer.rrset:
        try:
            ip_answer = resolver.query(name_server.target, dns.rdatatype.A)
        except Exception as ex:
            msg = "Exception %s on A lookup for %s (name server for %s): %s"
            logging.warning(msg, type(ex), name_server.target, domain, ex)
        for r in ip_answer.rrset:
            ips.append(r.address)
        try:
            ip_answer = resolver.query(name_server.target, dns.rdatatype.AAAA)
        except Exception as ex:
            msg = "Exception %s on AAAA lookup for %s (name server for %s): %s"
            logging.warning(msg, type(ex), name_server.target, domain, ex)
        for r in ip_answer.rrset:
            ips.append(r.address)
    return ips


def _soaping(domain, resultq, stopev):
    logging.debug("_soaping(%r, resultq, stopev) startup", domain)

    thread_stopev = {}
    while not stopev.is_set():
        # find the IP addresses to use
        server_ips = lookup_name_server_ips(domain)
        logging.debug("server_ips: %s", server_ips)
        if not server_ips:
            logging.warning("no name servers found for %r, retrying", domain)
            sleep_time = random.normalvariate(3.0, 0.1)
            stopev.wait(timeout=sleep_time)
            continue

        # create threads for these IP addresses
        for server_ip in server_ips:
            # stop existing thread, if present
            if server_ip in thread_stopev:
                thread_stopev[server_ip].set()
            # create a new thread
            ev = threading.Event()
            thread_stopev[server_ip] = ev
            t = threading.Thread(target=_auth_query_thread,
                                 args=("foo", server_ip, domain,
                                       dns.rdatatype.SOA, resultq, ev))
            t.start()

        # stop any other threads on IP addresses no longer in use
        for server_ip in thread_stopev:
            if server_ip not in server_ips:
                thread_stopev[server_ip].set()
                del thread_stopev[server_ip]

        # wait and check again in a while
        # TODO: base this on TTL
        sleep_time = random.normalvariate(3600.0, 0.1)
        stopev.wait(timeout=sleep_time)

    # stop any existing threads
    for ev in thread_stopev.values():
        ev.set()

    logging.debug("_soaping(%r, resultq, stopev) shutdown", domain)


def main():
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs=1, help="domain to check")
    args = parser.parse_args()
    try:
        q = queue.Queue()
        t = threading.Thread(target=_json_output_thread, args=(q, 300))
        t.start()
        ev = threading.Event()
        t = threading.Thread(target=_soaping, args=(args.domain[0], q, ev))
        t.start()
        t.join()
    except KeyboardInterrupt:
        # stop the authoritative query threads
        ev.set()
        # stop the JSON thread
        q.put(None)
        t.join()


if __name__ == "__main__":
    main()
