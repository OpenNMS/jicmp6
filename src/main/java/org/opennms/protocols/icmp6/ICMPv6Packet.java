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
 * ICMPPacket
 *
 * @author brozow
 */
public class ICMPv6Packet {
    
    public static final int CHECKSUM_INDEX = 2;
    public static final int HEADER_OFFSET_TYPE = 0;
    public static final int HEADER_OFFSET_CODE = 1;
    public static final int HEADER_OFFSET_CHECKSUM = 2;
    
    public enum Type {
        DestinationUnreachable(1),
        TimeExceeded(3),
        EchoRequest(128),
        EchoReply(129),

        // this is used to represent a type code that we have not handled
        Other(-1);
        
        
        private int m_code;
        private Type(int code) {
            m_code = code;
        }
        
        public int getCode() {
            return m_code;
        }
        
        public static Type toType(byte typeCode) {
            int code = (typeCode & 0xff);
            for(Type p : Type.values()) {
                if (code == p.getCode()) {
                    return p;
                }
            }
            return Other;
        }
        
    }

    ByteBuffer m_packetData;
    
    public ICMPv6Packet(byte[] bytes, int offset, int length) {
        this(ByteBuffer.wrap(bytes, offset, length));
    }
    
    public ICMPv6Packet(ByteBuffer ipPayload) {
        m_packetData = ipPayload;
    }
    
    public ICMPv6Packet(ICMPv6Packet icmpPacket) {
        this(icmpPacket.m_packetData.duplicate());
    }
    
    public ICMPv6Packet(int size) {
        this(ByteBuffer.allocate(size));
    }
    
    public int getPacketLength() {
        return m_packetData.limit();
    }
    
    public Type getType() {
        return Type.toType(m_packetData.get(HEADER_OFFSET_TYPE));
    }
    
    public void setType(Type t) {
        m_packetData.put(HEADER_OFFSET_TYPE, ((byte)(t.getCode())));
    }
    
    public int getCode() {
        return 0xff & m_packetData.get(HEADER_OFFSET_CODE);
    }

    public void setCode(int code) {
        m_packetData.put(HEADER_OFFSET_CODE, ((byte)code));
    }
    
    public int getChecksum() {
        return getUnsignedShort(HEADER_OFFSET_CHECKSUM);
    }
    
    public void setBytes(int index, byte[] b) {
        ByteBuffer payload = m_packetData;
        int oldPos = payload.position();
        try {
            payload.position(index);
            payload.put(b);
        } finally {
            payload.position(oldPos);
        }
    }

    public int makeUnsignedShort(byte b1, byte b0) {
        return 0xffff & (((b1 & 0xff) << 8) | 
                         ((b0 & 0xff) << 0));
    }

    public int getUnsignedShort(int index) {
        return m_packetData.getShort(index) & 0xffff;
    }

    public void setUnsignedShort(int index, int us) {
        m_packetData.putShort(index, ((short)(us & 0xffff)));
    }
    
    final public byte[] toBytes() {
        return m_packetData.array();
    }

}
