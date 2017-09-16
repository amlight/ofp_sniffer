#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import requests
import threading
from influxdb import InfluxDBClient
from apps.ofp_stats import OFStats


class InfluxClient(object):
    """Class responsible for connecting to InfluxDB and send data"""

    def __init__(self,
                 host='localhost',
                 port=8086,
                 db='root',
                 trigger_event=''):
        """Connect to influxdb

           Args:
                host: influxdb host
                port: influxdb port
                db: database name
                trigger_event: treading.Event to control plotting
        """
        self.logger = logging.getLogger(__name__)
        self.host = host
        self.port = port
        self.db = db
        self.stop_event = threading.Event()
        self.trigger_event = trigger_event  # This event will be set when a packet is received
        self._db_thread = 0
        self.sample_delay = 1  # 1 second
        self.db_client = InfluxDBClient(self.host, self.port, database=self.db)
        self.logger.debug(
            "InfluxDBClient is set as {0} {1} {2}".format(host, port, db))
        self._bootstrap_db()
        self._db_thread = threading.Thread(target=self._update_db).start()

    def _bootstrap_db(self):
        """Bootstrap database creation

        """
        try:
            self.db_client.create_database(dbname=self.db)
        except requests.ConnectionError as e:
            raise e

    def _update_packet_types(self):
        """Update OpenFlow version global stats on InfluxDB

        """
        for v, fields in OFStats().packet_types.items():
            json_body = [{
                "measurement":
                "OFP_messages",
                "tags": {
                    "OFP_version": v
                },
                "time":
                "{0}".format(datetime.datetime.utcnow().isoformat('T')),
                "fields":
                fields
            }]
            self.logger.debug(json_body)
            self.db_client.write_points(json_body)

    def _update_tcp_reconnects(self):
        """ Update the number of TCP Reconnects on InfluxDB

        """
        OFStats().num_reconnects
        json_body = [{
            "measurement":
            "OFP_messages",
            "tags": {
                "controllers": "tcp"
            },
            "time":
            "{0}".format(datetime.datetime.utcnow().isoformat('T')),
            "fields": {
                "reconnects": OFStats().num_reconnects
            }
        }]
        self.logger.debug(json_body)
        self.db_client.write_points(json_body)

    def _update_per_dpid(self):
        """ This method updates stats per dpid on InfluxDB
            TODO: currently, OFStats().per_dev_packet_type is empty

        """
        dpids = OFStats().per_dev_packet_types.keys()
        self.logger.debug("dpids: {0}".format(dpids))
        for dpid in dpids:
            json_body = [{
                "measurement":
                "OFP_messages",
                "tags": {
                    "dpid": dpid
                },
                "time":
                "{0}".format(datetime.datetime.utcnow().isoformat('T')),
                "fields":
                OFStats().per_dev_packet_types[dpid]
            }]
            self.logger.debug(json_body)
            self.db_client.write_points(json_body)

    def _update_db(self):
        """Thread that sends OFStats data to InfluxDB"""
        self.logger.debug('_update_db started')
        # This thread runs continuously until the event stop is set
        while not self.stop_event.is_set():
            # wait until timeout or when the event is set (i.e., when a packet is received)
            self.trigger_event.wait(self.sample_delay)
            self.trigger_event.clear()
            try:
                self._update_packet_types()
                # TODO: increment per dpid too
                # self._update_per_dpid()
                self._update_tcp_reconnects()
            except requests.exceptions.ConnectionError:
                self.logger.error("couldn't write data to influxdb.")
        self.logger.debug('_update_db stopped')
