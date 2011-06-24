package org.opennms.protocols.icmp6;

import java.nio.ByteBuffer;

public class ICMPv6EchoReply extends ICMPv6EchoPacket {
    
    public ICMPv6EchoReply(ICMPv6Packet icmpPacket) {
        super(icmpPacket);
    }
    
    public ByteBuffer getContentBuffer() {
        return getDataBuffer();
    }

    public boolean isValid() {
        ByteBuffer content = getContentBuffer();
        return content.limit() >= DATA_LENGTH && COOKIE == getCookie();
    }
    
    public boolean isEchoReply() {
        return Type.EchoReply.equals(getType());
    }

}