package com.github.wintleh.NetworkMonitor;

import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

public class App {
	
	
    public static void main(String[] args) {
    	
        try {
			
        	String ipNIC = "10.12.40.163";
        	InetAddress addr = InetAddress.getByName(ipNIC);
        	PcapNetworkInterface nif = Pcaps.getDevByAddress(addr);
        	
        	observeInterface(nif, 1, ipNIC);
        	
        } catch (UnknownHostException e) {
			e.printStackTrace();
			System.exit(1);
        } catch (PcapNativeException e) {
			e.printStackTrace();
			System.exit(1);
		}
    }
    
    /**
     * Monitors and records the amount of data going through the given network interface
     * 
     * @param nif The interface to observe
     * @param timeInterval The amount of time to wait (in seconds) before returning the data information
     */
    private static void observeInterface(PcapNetworkInterface nif, int timeInterval, String ipNIC) {
    	
    	int snapLen = 65536;
        int handleTimeout = 1000;		// 1 second, The amount of time the handle waits to get a packet
        PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
        int processTimeout = 10000;		// 10 seconds
        
    	try {
    		
			PcapHandle handle = nif.openLive(snapLen, mode, handleTimeout);
			
			processPackets(handle, timeInterval, processTimeout, ipNIC);
			
			handle.close();
			
		} catch (PcapNativeException e) {
			e.printStackTrace();
		}
    	
    }
    
    /**
     * Count how many packets come in every timeInterval (in seconds) and average the count of the packets to get the average number of packets (per second) over the previous timeInterval.
     * 
     * @param handle
     * @param timeInterval The number of seconds in between each report
     * @param timeout The time the program waits before it exits from a PcapNativeException
     */
    private static void processPackets(PcapHandle handle, int timeInterval, int timeout, String ipNIC) {
    	
    	int dataAmount = 0;
    	long now = System.currentTimeMillis();
    	long previousReset = now;
    	// TODO Instead of writing to this file, the data should be sent to the server
    	String file = "C:\\Users\\hunte\\Documents\\networkAnalysis\\data\\raw\\" + ipNIC + "_" + getCurrentDateTimeFileName() + ".csv"; // Creates file in the directory containing the analysis program
    	
    	// Write the header for the csv, overwrite previous data
    	write(file, "time,bytes/sec", false);
    	
    	// Loop until program is stopped
    	// TODO add a way to stop this loop
    	while(true) {
    		
    		// Attempt to read a packet from handle
    		try {
    			now = System.currentTimeMillis();
				Packet packet = handle.getNextPacketEx();
				
				// If there was no error then there was a packet read
				dataAmount += packet.length();
				
				// Check if it has been at least five seconds since the last reset
				if(now - previousReset > 1000 * timeInterval) {
					
					double bytesPerSec = (dataAmount * 1.0) / timeInterval;
					
					// Find average packets per second over the previous 5 seconds
					// Uses integer division to get a whole number
					System.out.printf("%f used %n%d bytes/sec%n%n",  bytesPerSec / 125000000.0, dataAmount);
					
					write(file, getCurrentDateTime() + ',' + (int) bytesPerSec, true);
					
					previousReset = now;
					dataAmount = 0;
				}
				
			}  catch (PcapNativeException e) {
				
				// Wait until the time since the last reset is greater than timeout
				// previousReset can only update if there is no exception thrown from getting the next packet
				if(now - previousReset > timeout) {
					e.printStackTrace();
					return; 		// Safe version of System.exit(1), allows the handle to close
				}
			}  catch (NotOpenException e) {
				// Indicates the handle was not opened
				e.printStackTrace();
				return; 			// Safe version of System.exit(1), allows the handle to close
			}	catch (EOFException e) {
				// Signals that an end of file or end of stream has been reached unexpectedly during input.
				return;								// TODO Return some type of notification to central server (unless a lack of data indicates an error with the program)
				
			}	catch (TimeoutException e) {		// Do nothing if this exception occurs
													// We do not care if there is not a packet to read
				
			}	
    	}
    }
    
    /**
     * Write data to file. Writes a newline character at the end of data.
     * 
     * @param file The path to the output file
     * @param data The data to write
     * @param append True: append data, False: Overwrite file with data
     */
    private static void write(String file, String data, Boolean append) {
    	
    	try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, append), StandardCharsets.UTF_8))) {
    	    writer.write(data + System.getProperty("line.separator"));
    	} 
    	catch (IOException e) {
    		e.printStackTrace();
			return;
    	}  
    }
    
    /**
     * Gets the current time in ISO-8601 UTC format
     * 
     * @return The current time in ISO-8601 UTC format
     */
    private static String getCurrentDateTime() {
    	return Instant.now().toString();
    }
    
    
    /**
     * Gets the current time in ISO_8601 UTC format and in a format to be used in a file name
     * 
     * @return The current time in ISO-8601 UTC format with all ":" and "." removed
     */
    private static String getCurrentDateTimeFileName() {
    	return getCurrentDateTime().replace(":", "").replace(".", "");
    }
}
