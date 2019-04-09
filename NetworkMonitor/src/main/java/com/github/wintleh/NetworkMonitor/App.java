package com.github.wintleh.NetworkMonitor;

import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Hashtable;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;

/**
 * 
 * 
 * @author davidcrafts
 *
 */
public class App {
	

    public static void main(String[] args) throws UnknownHostException, IOException {
    	
    	Scanner input = new Scanner(System.in);
    	
    	System.out.println("Make sure to back up the csv (Press any key and enter to continue)");
    	input.next();		// Wait until there is confirmation of the backup from the user
    	input.close();
    	
        try {
   
        	InetAddress addr= InetAddress.getLocalHost(); // gets localhost Ip address
        
        	PcapNetworkInterface nif = Pcaps.getDevByAddress(addr); //interface to observe
        	
        	observeInterface(nif, 1); //Method call
        	
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
     * @throws UnknownHostException 
     */
    private static void observeInterface(PcapNetworkInterface nif, int timeInterval) throws UnknownHostException {
    	
    	int snapLen = 65536;
        int handleTimeout = 1000;		// 1 second, The amount of time the handle waits to get a packet
        	PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
        int processTimeout = 10000;		// 10 seconds
        
    	try {
    		
			PcapHandle handle = nif.openLive(snapLen, mode, handleTimeout);
			
			processPackets(handle, timeInterval, processTimeout);
			
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
     * @throws UnknownHostException 
     */
	private static void processPackets(PcapHandle handle, int timeInterval, int timeout) throws UnknownHostException {
    	
    	int dataAmount = 0;
    	long now = System.currentTimeMillis();
    	long previousReset = now;
    	InetAddress addr= InetAddress.getLocalHost();// gets localhost Ip address and pc name
    	
    	//Bytes per second file path
    	String file = "/Users/davidcrafts/Dropbox/network-analysis-data/" + getIpAddress(addr.getAddress())  + "_" 
    			+ getCurrentDateTime().substring(0, 10) + ".csv";
    	
    	//Packet count file path
      	String file01 = "/Users/davidcrafts/Dropbox/network-analysis-data/" + getIpAddress(addr.getAddress())  + "_" 
    			+ getCurrentDateTime().substring(0, 10) + "_COUNT" + ".csv";
    
    	
    	// Write the header for the csv, overwrite previous data
    	write(file, "time,bytes/sec", false);
    	
    	
    	
      	//Declares hashtable for counting ip address instances 
    	Hashtable<String, String> ipTally = new Hashtable<String, String>(); 
    	
    	while(true) {
    
    		
    		try {
    			now = System.currentTimeMillis();
    			
    		 	// Attempt to read a packet from handle
				Packet packet = handle.getNextPacketEx(); 
				
				 //get the IP packet class
				 IpPacket ipPacket = packet.get(IpPacket.class);
				
				 try {
					 
				 //Gets destination IP address of a given packet 
				 String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress().toString(); 
				 
				 //If the hashtable already contains a given IP
				 if (ipTally.containsKey(dstIp)) {
						
						String count = ipTally.get(dstIp);
						
						//Increment hashtable instance, converts string to int then back
						int i = Integer.parseInt(count) +1;
						count = Integer.toString(i);
						
						//Puts updated count back into hashtable
						ipTally.put(dstIp, count );
						
					}
				 	else {
						//If not in hashtable, put the IP address and count at 1 in hashtable
						ipTally.put(dstIp, "1");
						
					}
				 }//END TRY
				 
				 catch(NullPointerException e) {
					 
					 
				 } //END CATCH
			
		
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
					
					
				}//END IF
				
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
 
			
    		//Writes hashtable to file for each run of the while loop
    		writeHashtable(file01, ipTally);
    	} //END WHILE LOOP
    	
    
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
     * 
     * Writes the hashtable to a CSV file
     * @param file
     * @param a
     */
    private static void writeHashtable(String file, Hashtable<String, String> a) {
    	String eol = System.getProperty("line.separator");
    
    
    	try (Writer writer = new FileWriter(file)) {	
    		//Writes header of file 
    		writer.append("IP Address").append(',').append("Packet Count").append(eol);
    		
    	//Writes hashtable out to file 
    	  for (Entry<String, String> entry : a.entrySet()) {
    	    writer.append(entry.getKey()).append(',').append(entry.getValue()).append(eol);         
    	  }
    	} catch (IOException ex) {
    	  ex.printStackTrace(System.err);
    	}
    }//END writeHashtable
    
    
    /**
     * Gets the current time in ISO-8601 format
     * 
     * @return The current time in ISO-8601 format
     */
    private static String getCurrentDateTime() {
    	return Instant.now().toString();
    }
      
    //By Wayan Saryada @ https://kodejava.org/how-do-i-convert-raw-ip-address-to-string/
    private static String getIpAddress(byte[] rawBytes) {
        int i = 4;
        StringBuilder ipAddress = new StringBuilder();
        for (byte raw : rawBytes) {
            ipAddress.append(raw & 0xFF);
            if (--i > 0) {
                ipAddress.append(".");
            }
        }
        return ipAddress.toString();
    }
     
    
} //END APP