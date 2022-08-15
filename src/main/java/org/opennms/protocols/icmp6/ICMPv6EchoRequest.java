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
 * ICMPEchoRequest
 *
 * @author brozow
 */
public class ICMPv6EchoRequest extends ICMPv6EchoPacket {
    
    public static final int PACKET_LENGTH = 64;


    public ICMPv6EchoRequest() {
        super(64);
        setType(Type.EchoRequest);
        setCode(0);
    }


    public ICMPv6EchoRequest(int size) {
        super(size);
        setType(Type.EchoRequest);
        setCode(0);
    }


    public ICMPv6EchoRequest(int id, int seqNum, long threadId) {
        this();
        
        setIdentifier(id);
        setSequenceNumber(seqNum);
        
        // data fields
        setThreadId(threadId);
        setCookie();
        // timestamp is set later

        // fill buffer with 'interesting' data
        ByteBuffer buf = getDataBuffer();
        for(int b = DATA_LENGTH; b < buf.limit(); b++) {
            buf.put(b, (byte)b);
        }

    }
    

    public ICMPv6EchoRequest(int id, int seqNum, long threadId, int size) {
        this(size);
        
        setIdentifier(id);
        setSequenceNumber(seqNum);
        
        // data fields
        setThreadId(threadId);
        setCookie();
        // timestamp is set later

        // fill buffer with 'interesting' data
        ByteBuffer buf = getDataBuffer();
        for(int b = DATA_LENGTH; b < buf.limit(); b++) {
            buf.put(b, (byte)b);
        }

    }
    

}
