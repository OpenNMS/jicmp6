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
