"""
    Module to receive an OFP_PORT_STATUS, an OFP_ERROR, or a TCP reconnect
    and send via Slack.
"""


import os
import requests
from libs.openflow.of10.dissector import get_port_status_reason, get_ofp_error
from apps.ofp_proxies import OFProxy


class Notifications(object):
    """ Send notifications to a Slack channel
    """

    def __init__(self, channel):
        """ Instantiate Notification class in case CLI option -N is
        provided

        Args:
            channel: Slack channel name
            webhook: URL
        """
        self.channel = channel
        self.webhook = os.environ["SLACK_API_TOKEN"]
        self.req = requests

    def get_content(self, pkt):
        """ Extract the content from the OpenFlow message received

        Args:
            msg: OpenFlow message
        Return:
            string using format '{"text":CONTENT}'
        """

        for msg in pkt.ofmsgs:
            if msg.ofp.header.message_type.value == 12:
                source = OFProxy().get_name(pkt.l3.s_addr, pkt.l4.source_port)
                reason = get_port_status_reason(msg.ofp.reason.value)
                txt = "Switch: %s Interface %s Changed. Reason: %s"
                return txt % (source, msg.ofp.desc.name, reason)

            elif msg.ofp.header.message_type.value == 1:
                source = OFProxy().get_name(pkt.l3.s_addr, pkt.l4.source_port)
                etype, ecode = get_ofp_error(msg.ofp.error_type.value,
                                             msg.ofp.code.value)
                txt = "Switch: %s Error - Type: %s Code: %s"
                return txt % (source, etype, ecode)

        return False

    def send_msg(self, of_msg):
        """ Send msg to Slack channel

        Args:
            of_msg: OpenFlow message

        """
        msg = self.get_content(of_msg)

        if isinstance(msg, str):

            response = self.req.post(
                self.webhook,
                json={"text": msg},
                headers={'Content-Type': 'application/json'}

            )
            if response.status_code != 200:
                raise ValueError(
                    'Request to Slack returned an error %s, the response is: %s'
                    % (response.status_code, response.text)
                )
