#!/usr/bin/env python

import datetime
import logging 
import os
import shutil
import socket
import sys
import urlparse
import zlib

from http_parser.http import HttpStream, NoMoreData, ParserError
from http_parser.reader import StringReader


dump_date = None
logging.basicConfig(level = logging.DEBUG)


class CuilRecord(object):
    def __init__(self, host, ip, port, path, response_code, response, original_header):
        self.host = host
        self.ip = ip
        self.port = port
        self.path = path
        self.response_code = response_code
        self.response = response
        self.decompressed_response = self.decompress(response)
        self.parsed_response = HttpStream(StringReader(self.decompressed_response))
        self.original_header = original_header
        self.arc1_record = None
        try:
            self.arc1_record = self.create_arc1_record()
        except NoMoreData:
            logging.warning("  HTTP parser failed on empty header '%s'", self.decompressed_response)
        except ParserError:
            logging.warning("  HTTP parser failed on '%s'", self.decompressed_response)
        except KeyError,k:
            logging.warning("  Couldn't find key %s in %s", k, self.parsed_response.headers().keys())
            logging.warning("  " + self.decompressed_response)
        except AttributeError,e:
            logging.warning("  Unexpected problem", exc_info = True)
        self.original = self.create_original()

    def decompress(self, data):
        return zlib.decompress(data)
    
    def get_url(self):
        protocol = socket.getservbyport(int(self.port))
        url = urlparse.urlunsplit((protocol, self.host, self.path, None, None))
        return url

    def get_ip(self):
        quads = [str(int(x, 16)) for x in self.ip[0:2], self.ip[2:4], self.ip[4:6], self.ip[6:8]]
        return ".".join(quads)

    def get_length(self):
        if "Content-Length" in self.parsed_response.headers():
            return self.parsed_response.headers()['Content-Length']
        else:
            return len(list(self.parsed_response))

    def get_content_type(self):
        if "Content-type" in self.parsed_response.headers():
            return self.parsed_response.headers()['Content-type']
        else:
            return "text/html"

    def get_date(self):
        global dump_date
        try:
            server_date = self.parsed_response.headers()['Date']
            server_date = datetime.datetime.strptime(server_date, "%a, %d %b %Y %H:%M:%S %Z")
            if not dump_date:
                dump_date = server_date
            if server_date - dump_date > datetime.timedelta(weeks = 1):
                # Probably a bad date. It's a week off from the general ones so far
                # Use the global date itself.
                pass
            else:
                # Change the global dump date to the new one
                dump_date = server_date
        except KeyError:
            pass
        return dump_date.strftime("%Y%m%d%H%M%S") #YYYYMMDDhhmmss

    def __repr__(self):
        return "<CuilRecord (host = '%s', ip = '%s', port = '%s', path = '%s', response_code = '%s')>"%(self.host, self.ip, self.port, self.path, self.response_code)


    def create_arc1_record(self):
        record = "\n%(url)s %(ip)s %(date)s %(ctype)s %(length)s\n%(content)s"
        vals = dict(url = self.get_url(),
                    ip = self.get_ip(),
                    date = self.get_date(),
                    ctype = self.get_content_type(),
                    length = self.get_length(),
                    content = self.decompressed_response)
        return record%vals

    def create_original(self):
        record = "%s%s"%(self.original_header, self.response)
        return record
    

class CuilDump(file):
    def next(self):
        while True:
            line = self.readline()
            if not line:
                raise StopIteration
            while not line.strip():
                line = self.readline()
            # 1-800-4memory.com 331b3348 80 / 1273 200 502 503723491 739
            host, ip, port, path, response_len, response_code, header_len, dummy, content_len = line.strip().split()
            response = self.read(int(content_len))
            try:
                ret = CuilRecord(host, ip, port, path, response_code, response, line)
                return ret
            except zlib.error:
                logging.warning("Decompress error found with \n %s\n", line)
            except NoMoreData:
                logging.warning("HTTP parse error found with \n %s\n %s", line, ret.decompressed_response)
            

def write_arcv1_header(arc_v1_file):
    header1 = "filedesc:///%(name)s %(creator_ip)s %(creation_date)s %(content_type)s %(header_len)d\n"
    header2 = "1 0 CUIL\nURL IP-Address ArchivArchivee-date Content-type Archive-length\n\n"
    vals = dict(name = os.path.basename(arc_v1_file.name),
                creator_ip = "127.0.0.1",
                creation_date = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S"),
                content_type = "text/plain",
                header_len = len(header2))
    header = header1%vals+header2
    arc_v1_file.write(header)


def main(input_file, output_arcv1_file, output_arcv2_file, output_rejects_file):
    good = 0
    bad = 0
    with CuilDump(input_file) as ip:
        with open(output_arcv1_file, "w") as op1:
            with open(output_arcv2_file,"w") as op2:
                with open(output_rejects_file,"w") as rej:
                    write_arcv1_header(op1)
                    for record in ip:
                        try:
                            if not record.arc1_record:
                                logging.warning("Couldn't handle %s [G: %d, B:%d]\n", record, good, bad)
                                rej.write(record.original)
                                bad +=1
                                continue
                            op1.write(record.arc1_record)
                            # op2.write(record.arc2_record)
                            good +=1
                        except Exception:
                            logging.warning("Couldn't handle %s [G: %d, B:%d]\n", record, good, bad, exc_info = True)
                            rej.write(record.original)
                            bad +=1
    print "%s Records written to '%s'. %d records rejected"% (good, output_arcv1_file, bad)
    return 0


if __name__ == "__main__":
    ipfile = sys.argv[1]
    opdir = ipfile+"_output"
    if os.path.exists(opdir):
        logging.info("Deleting %s",opdir)
        shutil.rmtree(opdir)
    os.mkdir(opdir)
    op_arcv1_file = opdir + "/" + ipfile+".v1.arc"
    op_arcv2_file = opdir + "/" + ipfile+".v2.arc"
    op_rejects_file = opdir + "/rejected"
    sys.exit(main(ipfile, op_arcv1_file, op_arcv2_file, op_rejects_file))
