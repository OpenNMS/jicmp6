/*
This file is part of the OpenNMS(R) Application.

OpenNMS(R) is Copyright (C) 2002-2007 The OpenNMS Group, Inc.  All rights reserved.
OpenNMS(R) is a derivative work, containing both original code, included code and modified
code that was published under the GNU General Public License. Copyrights for modified
and included code are below.

OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.

Modifications:

2011 Jun 23: Cloned from jicmp to implement icmpv6
2008 Dec 10: More win32 cleanup, should be windows-HANDLE and 64-bit safe
2008 Feb 05: Cleaned up win32 building, also merged patch from Alfred Reibenschuh <alfred.reibenschuh@it-austria.com>
2007 Jul 25: Updated to be in a separate library; split out IcmpSocket.h, autoconfized tests
2004 Oct 27: Handle Darwin 10.2 gracefully.
2003 Sep 07: More Darwin tweaks.
2003 Apr 26: Fixes byteswap issues on Solaris x86.
2003 Mar 25: Used unt64_t instead of unsigned long long.
2003 Feb 15: Bugfixes for Darwin.
2003 Feb 11: Bugfixes for Darwin.
2003 Feb 10: Bugfixes for Darwin.
2003 Feb 09: ICMP response time on Darwin.
2003 Feb 02: Initial Darwin port.
2002 Nov 26: Fixed build issues on Solaris.
2002 Nov 13: Added response times for ICMP.

Original code base Copyright (C) 1999-2001 Oculan Corp.  All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

For more information contact:
OpenNMS Licensing       <license@opennms.org>
http://www.opennms.org/
http://www.opennms.com/


Tab Size = 8

*/

#include <config.h>

#include "ICMPv6Socket.h"
#include <jni.h>

#ifdef IP_MAXPACKET
#define MAX_PACKET IP_MAXPACKET
#else
#define MAX_PACKET 65535
#endif

#ifdef __WIN32__
#define WIN32_LEAN_AND_MEAN
#undef errno
#define errno WSAGetLastError()

int gettimeofday (struct timeval *tv, void* tz)
{
	union {
		ULONG64 ns100; /*time since 1 Jan 1601 in 100ns units */
		FILETIME ft;
	} now;

	GetSystemTimeAsFileTime (&now.ft);
	tv->tv_usec = (long) ((now.ns100 / 10LL) % 1000000LL);
	tv->tv_sec = (long) ((now.ns100 - 116444736000000000LL) / 10000000LL);
	return (0);
}
#endif

#if 0
#pragma export on
#endif
#include "org_opennms_protocols_icmp6_ICMPv6Socket.h"
#if 0
#pragma export reset
#endif

#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 62
#endif

/**
* This method is used to lookup the instances java.io.FileDescriptor
* object and it's internal integer descriptor. This hidden integer
* is used to store the opened ICMP socket handle that was
* allocated by the operating system.
*
* If the descriptor could not be recovered or has not been
* set then a negative value is returned.
*
*/
static onms_socket getIcmpFd(JNIEnv *env, jobject instance)
{
	jclass	thisClass = NULL;
	jclass	fdClass   = NULL;

	jfieldID thisFdField    = NULL;
	jobject  thisFdInstance = NULL;

	jfieldID fdFdField = NULL;
	onms_socket	fd_value  = INVALID_SOCKET;

	/**
	* Find the class that describes ourself.
	*/
	thisClass = (*env)->GetObjectClass(env, instance);
	if(thisClass == NULL)
		goto end_getfd;

	/**
	* Find the java.io.FileDescriptor class
	*/
	thisFdField = (*env)->GetFieldID(env, thisClass, "m_rawFd", "Ljava/io/FileDescriptor;");
	if(thisFdField == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_getfd;

	(*env)->DeleteLocalRef(env, thisClass);
	thisClass = NULL;

	/**
	* Get the instance of the FileDescriptor class from
	* the instance of ourself
	*/
	thisFdInstance = (*env)->GetObjectField(env, instance, thisFdField);
	if(thisFdInstance == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_getfd;

	/**
	* Get the class object for the java.io.FileDescriptor
	*/
	fdClass = (*env)->GetObjectClass(env, thisFdInstance);
	if(fdClass == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_getfd;

	/**
	* Get the field identifier for the primitive integer
	* that is part of the FileDescriptor class.
	*/
#ifdef __WIN32__
	fdFdField = (*env)->GetFieldID(env, fdClass, "handle", "J");
#else
	fdFdField = (*env)->GetFieldID(env, fdClass, "fd", "I");
#endif
	if (fdFdField == NULL || (*env)->ExceptionOccurred(env) != NULL) {
		goto end_getfd;
	}

	(*env)->DeleteLocalRef(env, fdClass);
	fdClass = NULL;

	/**
	* Recover the value
	*/
#ifdef __WIN32__
	fd_value = (SOCKET)(*env)->GetLongField(env, thisFdInstance, fdFdField);
#else
	fd_value = (*env)->GetIntField(env, thisFdInstance, fdFdField);
#endif

	(*env)->DeleteLocalRef(env, thisFdInstance);

end_getfd:
	/**
	* method complete, value is INVALID_SOCKET unless the
	* entire method is successful.
	*/
	return fd_value;
}

static void setIcmpFd(JNIEnv *env, jobject instance, onms_socket fd_value)
{
	jclass	thisClass = NULL;
	jclass	fdClass   = NULL;

	jfieldID thisFdField    = NULL;
	jobject  thisFdInstance = NULL;

	jfieldID fdFdField = NULL;

	/**
	* Find the class that describes ourself.
	*/
	thisClass = (*env)->GetObjectClass(env, instance);
	if(thisClass == NULL)
		goto end_setfd;

	/**
	* Find the java.io.FileDescriptor class
	*/
	thisFdField = (*env)->GetFieldID(env, thisClass, "m_rawFd", "Ljava/io/FileDescriptor;");
	if(thisFdField == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_setfd;

	(*env)->DeleteLocalRef(env, thisClass);
	thisClass = NULL;

	/**
	* Get the instance of the FileDescriptor class from
	* the instance of ourself
	*/
	thisFdInstance = (*env)->GetObjectField(env, instance, thisFdField);
	if(thisFdInstance == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_setfd;

	/**
	* Get the class object for the java.io.FileDescriptor
	*/
	fdClass = (*env)->GetObjectClass(env, thisFdInstance);
	if(fdClass == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_setfd;

	/**
	* Get the field identifier for the primitive integer
	* that is part of the FileDescriptor class.
	*/
#ifdef __WIN32__
	fdFdField = (*env)->GetFieldID(env, fdClass, "handle", "J");
#else
	fdFdField = (*env)->GetFieldID(env, fdClass, "fd", "I");
#endif
	if(fdFdField == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_setfd;

	(*env)->DeleteLocalRef(env, fdClass);
	fdClass = NULL;

	/**
	* Set the value
	*/
#ifdef __WIN32__
	(*env)->SetLongField(env, thisFdInstance, fdFdField, fd_value);
#else
	(*env)->SetIntField(env, thisFdInstance, fdFdField, fd_value);
#endif
	(*env)->DeleteLocalRef(env, thisFdInstance);

end_setfd:
	/**
	* method complete, value is INVALID_SOCKET unless the
	* entire method is successful.
	*/
	return;
}

static jobject newInetAddress(JNIEnv *env, unsigned char addr[])
{
	jclass		addrClass;
	jmethodID	addrByAddressMethodID;
	jobject 	addrInstance = NULL;
	jbyteArray      addrArray = NULL;

	/**
	 * copy the address into a jbyteArray
         */
	addrArray = (*env)->NewByteArray(env, 16);
	if(addrArray != NULL && (*env)->ExceptionOccurred(env) == NULL)
	{
	      (*env)->SetByteArrayRegion(env, 
		      addrArray,
		      0,
		      (jsize)16,
		      (jbyte *)addr);
	}
	if ((*env)->ExceptionOccurred(env) != NULL)
	         goto end_inet;

	/**
	* load the class
	*/
	addrClass = (*env)->FindClass(env, "java/net/InetAddress");
	if(addrClass == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_inet;

	/**
	* Find the static method
	*/
	addrByAddressMethodID = (*env)->GetStaticMethodID(env,
		addrClass,
		"getByAddress",
		"([B)Ljava/net/InetAddress;");
	if(addrByAddressMethodID == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_inet;

	/*
	* Invoke it!
	*/
	addrInstance = (*env)->CallStaticObjectMethod(env,
		addrClass,
		addrByAddressMethodID,
		addrArray);

	(*env)->DeleteLocalRef(env, addrClass);
	(*env)->DeleteLocalRef(env, addrArray);
end_inet:

	return addrInstance;
}

static void getInetAddress(JNIEnv *env, jobject instance, unsigned char addr[])
{
	jclass		addrClass = NULL;
	jmethodID	addrArrayMethodID = NULL;
	jbyteArray	addrData = NULL;


	/**
	* load the class
	*/
	addrClass = (*env)->GetObjectClass(env, instance);
	if(addrClass == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_inet;

	/**
	* Find the method
	*/
	addrArrayMethodID = (*env)->GetMethodID(env,
		addrClass,
		"getAddress",
		"()[B");
	if(addrArrayMethodID == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_inet;

	addrData = (*env)->CallObjectMethod(env,instance,addrArrayMethodID);
	if(addrData == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_inet;

	/*
	* The byte array returned from java.net.InetAddress.getAddress()
	* (which was fetched above and is stored as a jbyteArray in addrData)
	* is in network byte order (high byte first, AKA big endian).
	* the value of addr is also in network byte order, so no
	* conversion needs to be performed.
	*/
	(*env)->GetByteArrayRegion(env,
		addrData,
		0,
		16,
		(jbyte *)addr);

	(*env)->DeleteLocalRef(env, addrClass);
	(*env)->DeleteLocalRef(env, addrData);

	end_inet:
		return;
}

static void throwError(JNIEnv *env, char *exception, char *errorBuffer)
{
	jclass ioException = (*env)->FindClass(env, exception);
	if (ioException != NULL)
	{
		(*env)->ThrowNew(env, ioException, errorBuffer);
	}
}

/*
* Opens a new raw socket that is set to send
* and receive the ICMP protocol. The protocol
* for 'icmp' is looked up using the function
* getprotobyname() and passed to the newly
* constructed socket.
*
* An exception is thrown if either of the
* getprotobyname() or the socket() calls fail.
*
* Class:     org_opennms_protocols_icmp6_ICMPv6Socket
* Method:    initSocket
* Signature: ()V
*/
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp6_ICMPv6Socket_initSocket (JNIEnv *env, jobject instance)
{
	onms_socket icmp_fd = INVALID_SOCKET;
	int sock_type = SOCK_RAW;
#ifdef __WIN32__
	int result;
	WSADATA info;

	result = WSAStartup(MAKEWORD(2,2), &info);
	if (result != 0)
	{
		char errBuf[128];
		sprintf(errBuf, "WSAStartup failed: %d", result);
		throwError(env, "java/net/IOException", errBuf);
		return;
	}

#endif


#if HAVE_GETENV
	if (getenv ("JICMP6_USE_SOCK_DGRAM") != NULL) {
		sock_type = SOCK_DGRAM;
   }
#endif
	icmp_fd = socket(PF_INET6, sock_type, IPPROTO_ICMPV6);

	if(icmp_fd == SOCKET_ERROR)
	{
		char	errBuf[128];	/* for exceptions */
		int	savedErrno  = errno;
		snprintf(errBuf, sizeof(errBuf), "System error creating ICMPv6 socket (%d, %s)", savedErrno, strerror(savedErrno));
		throwError(env, "java/net/SocketException", errBuf);
		return;
	}

	setIcmpFd(env, instance, icmp_fd);
	return;
}

/*
 * Class: org_opennms_protocols_icmp6_ICMPv6Socket
 * Method: setTrafficClass
 * Signature: (I)V;
 */
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp6_ICMPv6Socket_setTrafficClass (JNIEnv *env, jobject instance, jint tos)
{
    int iRC;

    /* Get the current file descriptor */
    onms_socket fd_value = getIcmpFd(env, instance);
    if((*env)->ExceptionOccurred(env) != NULL)
    {
        goto end_settos; /* jump to end if necessary */
    }
    else if(fd_value < 0)
    {
        throwError(env, "java/io/IOException", "Invalid Socket Descriptor");
        goto end_settos;
    }

#ifndef HAVE_SETSOCKOPT
	throwError(env, "java/io/IOException", "Invalid Socket Descriptor");
	goto end_settos;
#endif

    /* set the TOS options on the socket */
    iRC = setsockopt(fd_value, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
    if(iRC == SOCKET_ERROR)
    {
        /*
        * Error reading the information from the socket
        */
        char errBuf[256];
        int savedErrno = errno;
        snprintf(errBuf, sizeof(errBuf), "Error reading data from the socket descriptor (iRC = %d, fd_value = %d, %d, %s)", iRC, fd_value, savedErrno, strerror(savedErrno));
        throwError(env, "java/io/IOException", errBuf);
    }
end_settos:
    return;
}

/*
 * Class: org_opennms_protocols_icmp6_ICMPv6Socket
 * Method: allowFragmentation
 * Signature: (B)V;
 */
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp6_ICMPv6Socket_allowFragmentation (JNIEnv *env, jobject instance, jboolean dofragment)
{
	int iRC;
	int dontfragment = dofragment == JNI_TRUE? 0 : 1;

	/* Get the current file descriptor */
	onms_socket fd_value = getIcmpFd(env, instance);
	if((*env)->ExceptionOccurred(env) != NULL)
	{
		goto end_setfragment; /* jump to end if necessary */
	}
	else if(fd_value < 0)
	{
		throwError(env, "java/io/IOException", "Invalid Socket Descriptor");
		goto end_setfragment;
	}

#ifndef HAVE_SETSOCKOPT
	throwError(env, "java/io/IOException", "Invalid Socket Descriptor");
	goto end_setfragment;
#endif

    /* set the fragment option on the socket */
    iRC = setsockopt(fd_value, IPPROTO_IPV6, IPV6_DONTFRAG, &dontfragment, sizeof(dontfragment));
	if(iRC == SOCKET_ERROR)
	{
		/*
		* Error calling setsockopt
		*/
		char errBuf[256];
		int savedErrno = errno;
		snprintf(errBuf, sizeof(errBuf), "Error setting fragmentation bit on socket descriptor (iRC = %d, fd_value = %d, %d, %s)", iRC, fd_value, savedErrno, strerror(savedErrno));
		throwError(env, "java/io/IOException", errBuf);
	}
end_setfragment:
	return;
}


/*
* Class:     org_opennms_protocols_icmp6_ICMPv6Socket
* Method:    receive
* Signature: ()Ljava/net/DatagramPacket;
*/
JNIEXPORT jobject JNICALL
Java_org_opennms_protocols_icmp6_ICMPv6Socket_receive (JNIEnv *env, jobject instance)
{
	struct sockaddr_in6	inAddr;
	onms_socklen_t		inAddrLen;
	int			iRC;
	void *			inBuf = NULL;
	struct icmp6_hdr *	icmp6Hdr = NULL;

	jbyteArray		byteArray 	= NULL;
	jobject			addrInstance 	= NULL;
	jobject			datagramInstance = NULL;
	jclass			datagramClass 	= NULL;
	jmethodID		datagramCtorID 	= NULL;


	/**
	* Get the current descriptor's value
	*/
	onms_socket fd_value = getIcmpFd(env, instance);
	if((*env)->ExceptionOccurred(env) != NULL)
	{
		goto end_recv; /* jump to end if necessary */
	}
	else if(fd_value < 0)
	{
		throwError(env, "java/io/IOException", "Invalid Socket Descriptor");
		goto end_recv;
	}

	/**
	* Allocate a buffer to receive data if necessary.
	* This is probably more than necessary, but we don't
	* want to lose messages if we don't need to. This also
	* must be dynamic for MT-Safe reasons and avoids blowing
	* up the stack.
	*/
	inBuf = malloc(MAX_PACKET);
	if(inBuf == NULL)
	{
		throwError(env, "java/lang/OutOfMemoryError", "Failed to allocate memory to receive ICMPv6 datagram");
		goto end_recv;
	}
	memset(inBuf, 0, MAX_PACKET);

	/**
	* Clear out the address structures where the
	* operating system will store the to/from address
	* information.
	*/
	memset((void *)&inAddr, 0, sizeof(inAddr));
	inAddrLen = sizeof(inAddr);

	/**
	* Receive the data from the operating system. This
	* will also include the IP header that precedes
	* the ICMP data, we'll strip that off later.
	*/
	iRC = recvfrom(fd_value, inBuf, MAX_PACKET, 0, (struct sockaddr *)&inAddr, &inAddrLen);
	if(iRC == SOCKET_ERROR)
	{
		/*
		* Error reading the information from the socket
		*/
		char errBuf[256];
		int savedErrno = errno;
		snprintf(errBuf, sizeof(errBuf), "Error reading data from the socket descriptor (iRC = %d, fd_value = %d, %d, %s)", iRC, fd_value, savedErrno, strerror(savedErrno));
		throwError(env, "java/io/IOException", errBuf);
		goto end_recv;
	}
	else if(iRC == 0)
	{
		/*
		* Error reading the information from the socket
		*/
		throwError(env, "java/io/EOFException", "End-of-File returned from socket descriptor");
		goto end_recv;
	}

	icmp6Hdr = (struct icmp6_hdr *)((char *)inBuf);

	/**
	* Check the ICMP header for type ECHO_REPLY, and
	* then check the payload for the 'OpenNMS!' marker. If it's one
	* we sent out then fix the recv time!
	*
	* Don't forget to check for a buffer overflow!
	*/
	if(iRC >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		&& icmp6Hdr->icmp6_type == ICMP6_ECHO_REPLY
		&& memcmp((char *)icmp6Hdr + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0)
	{
		uint64_t now;
		uint64_t sent;
		uint64_t diff;

		/**
		* get the current time in microseconds and then
		* compute the difference
		*/
		CURRENTTIMEMICROS(now);
		memcpy((char *)&sent, (char *)icmp6Hdr + SENTTIME_OFFSET, TIME_LENGTH);
		sent = ntohll(sent);
		diff = now - sent;

		/*
		* Now fill in the sent, received, and diff
		*/
		sent = MICROS_TO_MILLIS(sent);
		sent = htonll(sent);
		memcpy((char *)icmp6Hdr + SENTTIME_OFFSET, (char *)&sent, TIME_LENGTH);

		now  = MICROS_TO_MILLIS(now);
		now  = htonll(now);
		memcpy((char *)icmp6Hdr + RECVTIME_OFFSET, (char *)&now, TIME_LENGTH);

		diff = htonll(diff);
		memcpy((char *)icmp6Hdr + RTT_OFFSET, (char *)&diff, TIME_LENGTH);

		/* no need to recompute checksum on this on
		* since we don't actually check it upon receipt
		*/
	}

	/**
	* Now construct a new java.net.InetAddress object from
	* the recipt information. The network address must
	* be passed in network byte order!
	*/
	addrInstance = newInetAddress(env, inAddr.sin6_addr.s6_addr);
	if(addrInstance == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_recv;

	/**
	* Get the byte array needed to setup
	* the datagram constructor.
	*/
	byteArray = (*env)->NewByteArray(env, (jsize)iRC);
	if(byteArray != NULL && (*env)->ExceptionOccurred(env) == NULL)
	{
		(*env)->SetByteArrayRegion(env,
			byteArray,
			0,
			(jsize)iRC,
			(jbyte *)icmp6Hdr);
	}
	if((*env)->ExceptionOccurred(env) != NULL)
		goto end_recv;

	/**
	* get the datagram class
	*/
	datagramClass = (*env)->FindClass(env, "java/net/DatagramPacket");
	if(datagramClass == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_recv;

	/**
	* datagram constructor identifier
	*/
	datagramCtorID = (*env)->GetMethodID(env,
		datagramClass,
		"<init>",
		"([BILjava/net/InetAddress;I)V");
	if(datagramCtorID == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_recv;

	/*
	* new one!
	*/
	datagramInstance = (*env)->NewObject(env,
		datagramClass,
		datagramCtorID,
		byteArray,
		(jint)iRC,
		addrInstance,
		(jint)0);

	/**
	* they will be deleted anyway,
	* but we're just speeding up the process.
	*/
	(*env)->DeleteLocalRef(env, addrInstance);
	(*env)->DeleteLocalRef(env, byteArray);
	(*env)->DeleteLocalRef(env, datagramClass);

end_recv:
	if(inBuf != NULL)
		free(inBuf);

	return datagramInstance;
}

/*
* Class:     org_opennms_protocols_icmp6_ICMPv6Socket
* Method:    send
* Signature: (Ljava/net/DatagramPacket;)V
*/
JNIEXPORT void JNICALL
Java_org_opennms_protocols_icmp6_ICMPv6Socket_send (JNIEnv *env, jobject instance, jobject packet)
{
	jclass		dgramClass;
	jmethodID	dgramGetDataID;
	jmethodID	dgramGetAddrID;

	jobject		addrInstance;
	jbyteArray	icmpDataArray;
	char *		outBuffer = NULL;
	jsize		bufferLen = 0;
	int		iRC;
	struct sockaddr_in6 Addr;


	/**
	* Recover the operating system file descriptor
	* so that we can use it in the sendto function.
	*/
	onms_socket icmpfd = getIcmpFd(env, instance);

	/**
	* Check for exception
	*/
	if((*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	/**
	* check the descriptor
	*/
	if(icmpfd < 0)
	{
		throwError(env, "java/io/IOException", "Invalid file descriptor");
		goto end_send;
	}

	/**
	* get the DatagramPacket class information
	*/
	dgramClass = (*env)->GetObjectClass(env, packet);
	if(dgramClass == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	/**
	* Get the identifiers for the getData() and getAddress()
	* methods that are part of the DatagramPacket class.
	*/
	dgramGetDataID = (*env)->GetMethodID(env, dgramClass, "getData", "()[B");
	if(dgramGetDataID == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	dgramGetAddrID = (*env)->GetMethodID(env, dgramClass, "getAddress", "()Ljava/net/InetAddress;");
	if(dgramGetAddrID == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	(*env)->DeleteLocalRef(env, dgramClass);
	dgramClass = NULL;

	/**
	* Set up the address
	*/

	memset(&Addr, 0, sizeof(Addr));
	Addr.sin6_family = AF_INET6;
	Addr.sin6_port   = 0;

	/**
	* Get the address information from the DatagramPacket
	* so that a useable Operating System address can
	* be constructed.
	*/
	addrInstance = (*env)->CallObjectMethod(env, packet, dgramGetAddrID);
	if(addrInstance == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	getInetAddress(env, addrInstance, Addr.sin6_addr.s6_addr);
	if((*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	/**
	* Remove local references that are no longer needed
	*/
	(*env)->DeleteLocalRef(env, addrInstance);
	addrInstance = NULL;

	/**
	* Get the byte[] data from the DatagramPacket
	* and then free up the local reference to the
	* method id of the getData() method.
	*/
	icmpDataArray = (*env)->CallObjectMethod(env, packet, dgramGetDataID);
	if(icmpDataArray == NULL || (*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	/**
	* Get the length of the buffer so that
	* a suitable 'char *' buffer can be allocated
	* and used with the sendto() function.
	*/
	bufferLen = (*env)->GetArrayLength(env, icmpDataArray);
	if(bufferLen <= 0)
	{
		throwError(env, "java/io/IOException", "Insufficient data");
		goto end_send;
	}

	/**
	* Allocate the buffer where the java byte[] information
	* is to be transfered to.
	*/
	outBuffer = malloc((size_t)bufferLen);
	if(outBuffer == NULL)
	{
		char buf[128]; /* error condition: java.lang.OutOfMemoryError! */
		int serror = errno;
		snprintf(buf, sizeof(buf), "Insufficent Memory (%d, %s)", serror, strerror(serror));

		throwError(env, "java/lang/OutOfMemoryError", buf);
		goto end_send;
	}

	/**
	* Copy the contents of the packet's byte[] array
	* into the newly allocated buffer.
	*/
	(*env)->GetByteArrayRegion(env,
		icmpDataArray,
		0,
		bufferLen,
		(jbyte *)outBuffer);
	if((*env)->ExceptionOccurred(env) != NULL)
		goto end_send;

	(*env)->DeleteLocalRef(env, icmpDataArray);

	/**
	* Check for 'OpenNMS!' at byte offset 32. If
	* it's found then we need to modify the time
	* and checksum for transmission. ICMP type
	* must equal 8 for ECHO_REQUEST
	*
	* Don't forget to check for a potential buffer
	* overflow!
	*/
	if(bufferLen >= (OPENNMS_TAG_OFFSET + OPENNMS_TAG_LEN)
		&& ((struct icmp6_hdr *)outBuffer)->icmp6_type == ICMP6_ECHO_REQUEST
		&& memcmp((char *)outBuffer + OPENNMS_TAG_OFFSET, OPENNMS_TAG, OPENNMS_TAG_LEN) == 0)
	{
		uint64_t now = 0;

		memcpy((char *)outBuffer + RECVTIME_OFFSET, (char *)&now, TIME_LENGTH);
		memcpy((char *)outBuffer + RTT_OFFSET, (char *)&now, TIME_LENGTH);

		CURRENTTIMEMICROS(now);
		now = htonll(now);
		memcpy((char *)outBuffer + SENTTIME_OFFSET, (char *)&now, TIME_LENGTH);

		/* checksum will be computed by system */
		((struct icmp6_hdr *)outBuffer)->icmp6_cksum = 0;

	}


	iRC = sendto(icmpfd,
		(void *)outBuffer,
		(int)bufferLen,
		0,
		(struct sockaddr *)&Addr,
		sizeof(Addr));

	if(iRC == SOCKET_ERROR && errno == EACCES)
	{
		throwError(env, "java/net/NoRouteToHostException", "cannot send to broadcast address");
	}
	else if(iRC != bufferLen)
	{
		char buf[128];
		int serror = errno;
		snprintf(buf, sizeof(buf), "sendto error (%d, %s)", serror, strerror(serror));
		throwError(env, "java/io/IOException", buf);
	}


end_send:
	if(outBuffer != NULL)
		free(outBuffer);

	return;
}

/*
* Class:     org_opennms_protocols_icmp6_ICMPv6Socket
* Method:    close
* Signature: ()V
*/
JNIEXPORT void
JNICALL Java_org_opennms_protocols_icmp6_ICMPv6Socket_close (JNIEnv *env, jobject instance)
{
	onms_socket fd_value = getIcmpFd(env, instance);
	if(fd_value >= 0 && (*env)->ExceptionOccurred(env) == NULL)
	{
		close(fd_value);
		setIcmpFd(env, instance, INVALID_SOCKET);
	}
#ifdef __WIN32__
	WSACleanup();
#endif
	return;
}
