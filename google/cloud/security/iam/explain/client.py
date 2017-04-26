#!/usr/bin/env python

import explain_pb2_grpc
import explain_pb2
import grpc
import time
import logging

def run(endpoint='localhost:50051'):
    logging.info("Running client")
    channel = grpc.insecure_channel(endpoint)
    logging.info("Connected")
    stub = explain_pb2_grpc.ExplainStub(channel)
    logging.info("Instantiated client stub")
    request = explain_pb2.PingRequest()
    logging.info("Created request")
    request.data = "hello"
    reply = stub.Ping(request)
    logging.info("Executed RPC")

    request = explain_pb2.GetAccessByResourcesRequest()
    request.expand_groups = False
    request.resource_name = 'vm1'
    request.permission_names.append('cloudsql.table.read')
    reply = stub.GetAccessByResources(request)
    for access in reply.accesses:
        print access

if __name__ == "__main__":
    import sys
    run(endpoint=sys.argv[1] if len(sys.argv) > 1 else 'localhost:50051')
