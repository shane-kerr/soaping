# TODO: figure out how to make initial log rotate name on the correct time
# TODO: get source IP address
# TODO: errors
# TODO: stats (queries sent, queries failed, etc.)
# TODO: TCP?
import argparse
import base64
import csv
import curses
import datetime
import errno
import io
import json
import logging
import logging.handlers
import queue
import random
import re
try:
    import selectors
except ImportError:
    import selectors34 as selectors
import socket
import ssl
import sys
import threading
import time

import dns.edns
import dns.message
import dns.query
import dns.rdatatype
import dns.rdtypes
import dns.resolver

# We will use the CLOCK_MONOTONIC_RAW if available, otherwise CLOCK_MONOTONIC.
CLOCK = getattr(time, 'CLOCK_MONOTONIC_RAW', getattr(time, 'CLOCK_MONOTONIC'))

def _auth_query_thread(name_server, target_ip, qname, qtype, resultqs, stopev):
    logging.debug("_auth_query_thread(%r, %r, %r, %r, ...) startup",
                  name_server, target_ip, qname, qtype)
    nsid_option = dns.edns.GenericOption(dns.edns.NSID, b'')
    query = dns.message.make_query(qname, qtype, options=[nsid_option])
    while not stopev.is_set():
        query.id = random.randint(0, 65535)
        timestamp = time.time()
        time_a = time.clock_gettime(CLOCK)
        try:
            answer = dns.query.udp(query, where=target_ip, timeout=1,
                                   ignore_unexpected=True)
            time_b = time.clock_gettime(CLOCK)
            rt = time_b - time_a
            nsid = get_nsid(answer)
            serial = get_serial(answer)
            for resultq in resultqs:
                resultq.put((name_server, target_ip, query,
                             timestamp, rt, answer, nsid, serial))
            # log this at an even lower level than debug
            logging.log(5, "query -t %s %s @%s => %.4f seconds # %s",
                        dns.rdatatype.to_text(qtype), qname,
                        target_ip, (time_b-time_a), name_server)
        except dns.exception.Timeout:
            time_b = time.clock_gettime(CLOCK)
            rt = time_b - time_a
            for resultq in resultqs:
                resultq.put((name_server, target_ip, query,
                             timestamp, rt, None, None, None))
            logging.debug("Timeout querying -t %s %s @%s # %s",
                          dns.rdatatype.to_text(qtype), qname, target_ip,
                          name_server)
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
                  name_server, target_ip, qname, qtype)


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
        json_log.info(json.dumps(d))


def get_nsid(msg):
    for opt in msg.options:
        if opt.otype == dns.edns.NSID:
            return opt.data.decode()
    return None


def get_serial(msg):
    for rrset in msg.answer:
        if rrset.rdtype == dns.rdatatype.SOA:
            return rrset[0].serial
    return None


def _csv_log_namer(name):
    return re.sub(r'\.csv', '', name) + ".csv"


def _csv_output_thread(resultq, interval):
    csv_log = logging.getLogger('CSV output')
    csv_log.propagate = False

    csv_buf = io.StringIO()
    csv_writer = csv.writer(csv_buf)

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
    rh = logging.handlers.TimedRotatingFileHandler("soaping.csv",
                                                   when=when,
                                                   interval=interval,
                                                   utc=True)
    rh.namer = _csv_log_namer
    csv_log.addHandler(rh)
    csv_log.setLevel(logging.INFO)

    while True:
        result = resultq.get()
        if result is None:
            break

        if extra_rollover and time.time() >= extra_rollover:
            rh.doRollover()
            extra_rollover = None

        # 3rd part of tuple is the question message
        # you can get the qname in query.question[0].name
        name_server, target_ip, _, timestamp, rt, answer, nsid, serial = result
        when_dt = datetime.datetime.fromtimestamp(timestamp,
                                                  tz=datetime.timezone.utc)
        when = when_dt.strftime("%Y%m%dT%H%M%S.%f")
        if nsid is None:
            nsid = ""
        if serial is None:
            serial = "-"

        csv_writer.writerow([serial, when, "%.6f" % rt,
                             name_server, target_ip, nsid])
        csv_line = csv_buf.getvalue()
        csv_buf.seek(0)
        csv_buf.truncate(0)
        csv_log.info(csv_line[:-1])


def _tls_tunnel_listener(socket_in, target_addr):
    """Only handle a single connection at a time."""
    logging.debug("_tls_tunnel_listener(%r, %r) startup",
                  socket_in, target_addr)
    while True:
        sel = None
        client_socket = None
        socket_out = None
        ssl_socket_out = None

        try:
            client_socket, client_addr = socket_in.accept()
            logging.debug("tunnel client connected from %r", client_addr)
            socket_out = socket.create_connection(target_addr)
            logging.debug("tunnel connected to %r", target_addr)
            ssl_socket_out = ssl.wrap_socket(socket_out)
            sel = selectors.DefaultSelector()
            sel.register(client_socket, selectors.EVENT_READ, ssl_socket_out)
            sel.register(ssl_socket_out, selectors.EVENT_READ, client_socket)
            connected = True
            while connected:
                for key, mask in sel.select():
                    data = key.fileobj.recv(18000)
                    if len(data) == 0:
                        connected = False
                    else:
                        key.data.sendall(data)
            logging.debug("tunnel closed")
        except Exception as ex:
            logging.warning("TLS tunnel error: %s", ex)

        del sel
        if ssl_socket_out:
            ssl_socket_out.close()
        if socket_out:
            socket_out.close()
        if client_socket:
            client_socket.close()


def _start_tunnel(target_addr, ready_ev):
    """Set up an internal tunnel to the given address,
    return the address we are listening on."""
    socket_in = socket.socket()
    socket_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_in.bind(('127.0.0.1', 0))
    socket_in.listen(1)
    t = threading.Thread(target=_tls_tunnel_listener,
                         args=(socket_in, target_addr),
                         daemon=True)
    t.start()
    ready_ev.set()
    return socket_in.getsockname()


def lookup_name_server_ips(domain, resolver_ip, use_tls):
    use_tcp = False
    resolver = dns.resolver.Resolver()
    # TODO: set timeout
    if resolver_ip:
        if use_tls:
            logging.debug("tunnel closed")
            tunnel_ready_ev = threading.Event()
            tunnel = _start_tunnel((resolver_ip, 853), tunnel_ready_ev)
            resolver.nameservers = [tunnel[0]]
            resolver.port = tunnel[1]
            use_tcp = True
            tunnel_ready_ev.wait()
        else:
            resolver.nameservers = [resolver_ip]
    try:
        answer = resolver.query(domain, dns.rdatatype.NS, tcp=use_tcp)
    except Exception as ex:
        logging.error("Unexpected %s exception for NS lookup of %s: %s",
                      type(ex), domain, ex)
        return None

    name_server_ips = {}
    # XXX: could do more verification of the answer, such as class, etc.
    if answer.rdtype == dns.rdatatype.NS:
        for rdata in answer.rrset.items:
            name_server = rdata.target.to_text()
            name_server_ips[name_server] = []
            try:
                ip_answer = resolver.query(name_server, dns.rdatatype.A,
                                           tcp=use_tcp)
                for r in ip_answer.rrset:
                    name_server_ips[name_server].append(r.address)
            except dns.resolver.NoAnswer:
                # we get this if we have no A records for the name server
                pass
            except Exception as ex:
                msg = "Exception %s on A lookup for %s "\
                      "(name server for %s): %s"
                logging.warning(msg, type(ex), name_server, domain, ex)
            try:
                ip_answer = resolver.query(name_server, dns.rdatatype.AAAA,
                                           tcp=use_tcp)
                for r in ip_answer.rrset:
                    name_server_ips[name_server].append(r.address)
            except dns.resolver.NoAnswer:
                # we get this if we have no AAAA records for the name server
                pass
            except Exception as ex:
                msg = "Exception %s on AAAA lookup for %s "\
                      "(name server for %s): %s"
                logging.warning(msg, type(ex), name_server, domain, ex)

    return name_server_ips


def _soaping(domain, resolver_ip, use_tls, resultqs, stopev):
    logging.debug("_soaping(%r, resultqs, stopev) startup", domain)

    thread_stopev = {}
    while not stopev.is_set():
        # find the IP addresses to use
        server_ips = lookup_name_server_ips(domain, resolver_ip, use_tls)
        logging.debug("server_ips: %s", server_ips)
        if not server_ips:
            logging.warning("no name servers found for %r, retrying", domain)
            sleep_time = random.normalvariate(3.0, 0.1)
            stopev.wait(timeout=sleep_time)
            continue

        # create threads for these IP addresses
        cur_thread_id = set()
        for name_server, server_ips in server_ips.items():
            for server_ip in server_ips:
                thread_id = name_server + "@" + server_ip
                cur_thread_id.add(thread_id)

                # stop existing thread, if present
                if thread_id in thread_stopev:
                    thread_stopev[thread_id].set()
                # create a new thread
                ev = threading.Event()
                thread_stopev[thread_id] = ev
                t = threading.Thread(target=_auth_query_thread,
                                     args=(name_server, server_ip, domain,
                                           dns.rdatatype.SOA, resultqs, ev))
                t.start()

        # stop any other threads on IP addresses no longer in use
        to_del = []
        for thread_id in thread_stopev:
            if thread_id not in cur_thread_id:
                thread_stopev[thread_id].set()
                to_del.append(thread_id)
        for thread_id in to_del:
            del thread_stopev[thread_id]

        # wait and check again in a while
        # TODO: base this on TTL
        sleep_time = random.normalvariate(3600.0, 0.1)
        stopev.wait(timeout=sleep_time)

    # stop any existing threads
    for ev in thread_stopev.values():
        ev.set()

    logging.debug("_soaping(%r, resultqs, stopev) shutdown", domain)


# TODO: smoothed/average RTT
# TODO: screen resize
def ui(scr, domain, cursesq):
    serials = {}
    errors = []
    last_refresh = 0
    while True:
        try:
            item = cursesq.get(timeout=0.25)
            if isinstance(item, tuple):
                (name_server, target_ip, query,
                 timestamp, rt, answer, nsid, serial) = item
                if not answer:
                    rt = None
                host_id = (name_server, target_ip)
                for serial in serials:
                    if host_id in serials[serial]:
                        del serials[serial][host_id]
                if not serial in serials:
                    serials[serial] = {}
                serials[serial][host_id] = (name_server, target_ip, rt)
            elif isinstance(item, logging.LogRecord):
                errors = [item] + errors
        except queue.Empty:
            pass
        # check time and write here
        now = time.clock_gettime(CLOCK)
        if now - last_refresh > 1:
            last_refresh = now
            # start with a blank screen
            scr.erase()
            scr_hig, scr_wid = scr.getmaxyx()
            scr.addstr(0, 0, "soaping " + domain)
            timestr = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            scr.addstr(0, scr_wid - len(timestr) - 2, timestr)
            # get the width for the name server and IP columns
            ns_width = len("Name Server")
            ip_width = len("IP")
            for serial in serials.keys():
                for name_server, target_ip, rt in serials[serial].values():
                    ns_width = max(len(name_server), ns_width)
                    ip_width = max(len(target_ip), ip_width)
            # output our results
            line = 2
            for serial in sorted(serials.keys()):
                scr.addstr(line, 0, "Serial [ %d ]" % serial)
                scr.addstr(line+1, 0, "Name Server".ljust(ns_width) + "  " +
                                      "IP".ljust(ip_width) + "  RTT msec")
                line += 2
                for host_id in sorted(serials[serial].keys()):
                    name_server, target_ip, rt = serials[serial][host_id]
                    if rt:
                        print_rt = "%3d" % (rt * 1000)
                    else:
                        print_rt = "  -"
                    scr.addstr(line, 0, name_server.ljust(ns_width) + "  " + 
                                        target_ip.ljust(ip_width) + "       " +
                                        print_rt)
                    line += 1
                line += 1
            # output our errors
#            err_idx = 0
#            while (err_idx < len(errors)) and (line < scr_hig):
#                scr.addstr(line, 0, str(dir(errors[err_idx])))
#                err_idx += 1
#                line += 1
#                scr.getch()
            # position the cursor at the bottom
            scr.move(scr_hig-1, scr_wid-1)
            scr.refresh()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain", nargs=1, help="domain to check")
    parser.add_argument("-r", "--resolver", help="IP address of resolver")
    parser.add_argument("-t", "--tls", action='store_true',
                        help="Use TLS to resolver")
    args = parser.parse_args()
    if args.resolver is not None:
        try:
            socket.inet_pton(socket.AF_INET6, args.resolver)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET, args.resolver)
            except OSError:
                print("Bad IP address '%s'" % args.resolver, file=sys.stderr)
                sys.exit(1)

    # Use an internal queue for logging, which we will then 
    # send to the curses display.
    cursesq = queue.Queue()
    logq_handler = logging.handlers.QueueHandler(cursesq)
    qlogger = logging.getLogger()
    qlogger.addHandler(logq_handler)
    qlogger.setLevel(logging.DEBUG)
#    logging.basicConfig(level=logging.DEBUG)

    # Start our CSV output thread.
    csvq = queue.Queue()
    t = threading.Thread(target=_csv_output_thread, args=(csvq, 1800))
    t.start()

    # Start our actual DNS query master thread.
    queues = (cursesq, csvq)
    ev = threading.Event()
    t = threading.Thread(target=_soaping,
                         args=(args.domain[0], args.resolver, args.tls,
                               queues, ev))
    t.start()

    try:
        curses.wrapper(ui, args.domain[0], cursesq)
    except KeyboardInterrupt:
        print("Shutting down...", end='', flush=True)
        # stop the authoritative query threads
        ev.set()
        # stop the CSV thread
        csvq.put(None)
        t.join()
        print("done")


if __name__ == "__main__":
    main()
