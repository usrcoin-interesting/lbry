#!/usr/bin/env python
#
# This library is free software, distributed under the terms of
# the GNU Lesser General Public License Version 3, or any later version.
# See the COPYING file included in this archive
#
# The docstrings in this module contain epytext markup; API documentation
# may be created by processing this file with epydoc: http://epydoc.sf.net

from lbrynet.dht.constants import COMPAT_VERSION
import msgtypes


class MessageTranslator(object):
    """ Interface for RPC message translators/formatters

    Classes inheriting from this should provide a translation services between
    the classes used internally by this Kademlia implementation and the actual
    data that is transmitted between nodes.
    """

    def fromPrimitive(self, msgPrimitive):
        """ Create an RPC Message from a message's string representation

        @param msgPrimitive: The unencoded primitive representation of a message
        @type msgPrimitive: str, int, list or dict

        @return: The translated message object
        @rtype: entangled.kademlia.msgtypes.Message
        """

    def toPrimitive(self, message):
        """ Create a string representation of a message

        @param message: The message object
        @type message: msgtypes.Message

        @return: The message's primitive representation in a particular
                 messaging format
        @rtype: str, int, list or dict
        """


class DefaultFormat(MessageTranslator):
    """ The default on-the-wire message format for this library """
    typeRequest, typeResponse, typeError = range(3)
    headerCompVer, headerType, headerMsgID, headerNodeID, headerNodeIP, headerNodePort = range(6)
    headerPayload, headerArgs = range(6, 8)

    def fromPrimitive(self, msgPrimitive):
        if msgPrimitive[self.headerCompVer] != COMPAT_VERSION:
            raise Exception('Received packet with comapt version %d, expected %d' %
                            (msgPrimitive[self.headerCompVer], COMPAT_VERSION))

        msgType = msgPrimitive[self.headerType]
        ip = ".".join([str(d) for d in msgPrimitive[self.headerNodeIP][:4]])
        if msgType == self.typeRequest:
            msg = msgtypes.RequestMessage(msgPrimitive[self.headerNodeID],
                                          ip,
                                          msgPrimitive[self.headerNodePort],
                                          msgPrimitive[self.headerPayload],
                                          msgPrimitive[self.headerArgs],
                                          msgPrimitive[self.headerMsgID])
        elif msgType == self.typeResponse:
            msg = msgtypes.ResponseMessage(msgPrimitive[self.headerMsgID],
                                           msgPrimitive[self.headerNodeID],
                                           ip,
                                           msgPrimitive[self.headerNodePort],
                                           msgPrimitive[self.headerPayload])
        elif msgType == self.typeError:
            msg = msgtypes.ErrorMessage(msgPrimitive[self.headerMsgID],
                                        msgPrimitive[self.headerNodeID],
                                        ip,
                                        msgPrimitive[self.headerNodePort],
                                        msgPrimitive[self.headerPayload],
                                        msgPrimitive[self.headerArgs])
        else:
            # Unknown message, no payload
            msg = msgtypes.Message(msgPrimitive[self.headerMsgID], msgPrimitive[self.headerNodeID],
                                   ip,
                                   msgPrimitive[self.headerNodePort])
        return msg

    def toPrimitive(self, message):
        msg = {self.headerCompVer: COMPAT_VERSION,
               self.headerMsgID: message.id,
               self.headerNodeID: message.nodeID,
               self.headerNodeIP: [int(x) for x in message.nodeIP.split('.')],
               self.headerNodePort: message.nodePort}
        if isinstance(message, msgtypes.RequestMessage):
            msg[self.headerType] = self.typeRequest
            msg[self.headerPayload] = message.request
            msg[self.headerArgs] = message.args
        elif isinstance(message, msgtypes.ErrorMessage):
            msg[self.headerType] = self.typeError
            msg[self.headerPayload] = message.exceptionType
            msg[self.headerArgs] = message.response
        elif isinstance(message, msgtypes.ResponseMessage):
            msg[self.headerType] = self.typeResponse
            msg[self.headerPayload] = message.response
        return msg
