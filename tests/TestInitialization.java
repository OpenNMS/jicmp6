import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;

import org.opennms.protocols.icmp6.ICMPv6EchoReply;
import org.opennms.protocols.icmp6.ICMPv6EchoRequest;
import org.opennms.protocols.icmp6.ICMPv6Packet;
import org.opennms.protocols.icmp6.ICMPv6Packet.Type;
import org.opennms.protocols.icmp6.ICMPv6Socket;



public class TestInitialization {

	public static void main(final String[] args) {
		try {
			final ICMPv6Socket socket = new ICMPv6Socket();
			
			Runnable r = new Runnable() {
			    public void run() {
			        System.err.println("Starting receiver");
			        while(true) {
			            try {
                            processReply(socket);
                        } catch (IOException e) {
                            e.printStackTrace();
                            System.exit(1);
                        }
			        }
			    }

                private void processReply(final ICMPv6Socket socket)
                        throws IOException {
                    
                    //System.err.println("Waiting for packet");
                    DatagramPacket responsePacket = socket.receive();

			        ICMPv6Packet icmpPacket = new ICMPv6Packet(responsePacket.getData(), responsePacket.getOffset(), responsePacket.getLength());
			        //System.err.printf("Recieved packet of type %s\n", icmpPacket.getType());
			        if (icmpPacket.getType() == Type.EchoReply) {
			            ICMPv6EchoReply reply = new ICMPv6EchoReply(icmpPacket);
			            double rtt = reply.getRoundTripTime()/1000.0;
			            String host = responsePacket.getAddress().getHostAddress();
			            System.err.printf("%d bytes from %s, icmp_seq=%d time=%f\n", responsePacket.getLength(), host, reply.getSequenceNumber(), rtt);
			        }
                }
			};
			
			Thread receiver = new Thread(r);
			receiver.start();
			
			int id = (int)(Math.random()*Short.MAX_VALUE);
			long threadId = (long)(Math.random()*Integer.MAX_VALUE);
			
			for(int seqNum = 0; seqNum < 10; seqNum++) {
			
			    ICMPv6EchoRequest request = new ICMPv6EchoRequest(id, seqNum, threadId);
			
			    byte[] bytes = request.toBytes();
			    DatagramPacket packet = new DatagramPacket(bytes, 0, bytes.length, InetAddress.getByName("::1"), 0);
            
			    //System.err.println("Sending packet\n");
			    socket.send(packet);
			    
			    Thread.sleep(1000);
			}
			
			
		} catch (final Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
		System.exit(0);
	}

}
