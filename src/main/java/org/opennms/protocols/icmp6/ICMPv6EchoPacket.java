/*
 * This file is part of JICMP6.
 *
 * JICMP6 is Copyright (C) 2011-2022 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2022 The OpenNMS Group, Inc.
 * 
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 * 
 * JICMP6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License, as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * JICMP6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with JICMP6. If not, see:
 *      http://www.gnu.org/licenses/
 * 
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.com>
 *     http://www.opennms.com/
 */
package org.opennms.protocols.icmp6;

import java.nio.ByteBuffer;


/**
 * ICMPEchoReply
 *
 * @author brozow
 */
public class ICMPv6EchoPacket extends ICMPv6Packet {

    // This long is equivalent to 'OpenNMS!' in ascii
    public static final long COOKIE = 0x4F70656E4E4D5321L;
    
    // offsets for TYPE, CODE and CHECK_SUM defined in ICMPv6Packet
    public static final int HEADER_OFFSET_IDENTIFIER = 4;
    public static final int HEADER_OFFSET_SEQUENCE_NUMBER = 6;
    public static final int HEADER_LENGTH = 8;

    // Packet payload format
    public static final int DATA_OFFSET_SENTTIME = 0;
    public static final int DATA_OFFSET_RECVTIME = 8;
    public static final int DATA_OFFSET_THREAD_ID = 16;
    public static final int DATA_OFFSET_RTT = 24;
    public static final int DATA_OFFSET_COOKIE = 32;
    public static final int DATA_LENGTH = 8*5;
    
    private final ByteBuffer m_dataBuffer;
    
    public ICMPv6EchoPacket(int size) {
        super(size);
        ByteBuffer content = m_packetData.duplicate();
        content.position(HEADER_LENGTH);
        m_dataBuffer = content.slice();
    }

    public ICMPv6EchoPacket(ICMPv6Packet icmpPacket) {
        super(icmpPacket);
        ByteBuffer content = m_packetData.duplicate();
        content.position(HEADER_LENGTH);
        m_dataBuffer = content.slice();
    }
    
    public ByteBuffer getDataBuffer() {
        return m_dataBuffer;
    }
    
    public int getIdentifier() {
        return getUnsignedShort(HEADER_OFFSET_IDENTIFIER);
    }
    
    public void setIdentifier(int id) {
        setUnsignedShort(HEADER_OFFSET_IDENTIFIER, id);
    }
    
    public int getSequenceNumber() {
        return getUnsignedShort(HEADER_OFFSET_SEQUENCE_NUMBER);
    }
    
    public void setSequenceNumber(int sn) {
        setUnsignedShort(HEADER_OFFSET_SEQUENCE_NUMBER, sn);
    }
    
    public long getSentTime() {
        return getDataBuffer().getLong(DATA_OFFSET_SENTTIME);
    }
    
    public void setSentTime(long sentTime) {
        getDataBuffer().putLong(DATA_OFFSET_SENTTIME, sentTime);
    }


    public long getReceiveTime() {
        return getDataBuffer().getLong(DATA_OFFSET_RECVTIME);
    }
    
    public void setReceiveTime(long recvTime) {
        getDataBuffer().putLong(DATA_OFFSET_RECVTIME, recvTime);
    }

    public long getThreadId() {
        return getDataBuffer().getLong(DATA_OFFSET_THREAD_ID);
    }
    
    public void setThreadId(long threadId) {
        getDataBuffer().putLong(DATA_OFFSET_THREAD_ID, threadId);
    }

    public long getRoundTripTime() {
        return getDataBuffer().getLong(DATA_OFFSET_RTT);
    }
    
    public void setRoundTripTime(long rtt) {
        getDataBuffer().putLong(DATA_OFFSET_RTT, rtt);
    }

    public long getCookie() {
        return getDataBuffer().getLong(DATA_OFFSET_COOKIE);
    }
    public void setCookie() {
        getDataBuffer().putLong(DATA_OFFSET_COOKIE, COOKIE);
    }
    


}
