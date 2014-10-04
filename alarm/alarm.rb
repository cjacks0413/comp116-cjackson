require 'packetfu' 
require 'apachelogregex'


$incident_number = 0 

def printIncident(attack, source_ip, protocol, payload, isWebLog)
        output = "#{$incident_number}. ALERT: #{attack} is detected from "\
             "(#{source_ip}) (#{protocol}) "
	if isWebLog 
		output += " (#{payload})"
	else 
            	output += " (#{payload.each_byte.map { |b| sprintf(" 0x%02X ",b) }.join})!"
	end 
	puts output 
	$incident_number += 1 
end

def detectNullOrXmasScan(pkt) 
	if pkt.proto().include? "TCP"
		if pkt.tcp_header.tcp_flags.select { |f| f != 0 }.empty?
			printIncident("NULL scan", pkt.ip_saddr, "TCP", pkt.payload(), false)			
		elsif (pkt.tcp_header.tcp_flags.fin != 0 &&  
		     		pkt.tcp_header.tcp_flags.psh != 0 &&
	               		pkt.tcp_header.tcp_flags.urg != 0 )
			printIncident("XMAS scan", pkt.ip_saddr, "TCP", pkt.payload(), false)
		end
	end 
end 

def detectCreditCardInTheClear(pkt)
	results = ((pkt.payload().scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)) ||
	   	  (pkt.payload().scan(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)) ||
		  (pkt.payload().scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/)) ||
                  (pkt.payload().scan(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/)))
	if !results.empty? 
		protocols = ""
		pkt.proto().each_with_index do |p, i|
			if i == pkt.proto().length - 1
				protocols += "#{p}"
			else
				protocols += "#{p}/" 
			end
		end
		printIncident("Credit Card leaked in the clear", pkt.ip_saddr, protocols, pkt.payload(), false)
	end 
end
 
def analyzePacket(packet) 
	pkt = PacketFu::Packet.parse(packet)
	detectNullOrXmasScan(pkt)
	detectCreditCardInTheClear(pkt) 
end 


def analyzePacketStream
	cap = PacketFu::Capture.new(:start => true, :promisc => true,  
				  :iface => "eth0")
	cap.stream.each do |p|
		analyzePacket(p) 	
	end 	
end   

def analyzeWebServerLog(file)
	format = '%source %l %u %t \"%request\" %>status %b \"%{Referer}i\" \"%{User-Agent}i\"'
	parser = ApacheLogRegex.new(format)
	logs = []
	File.open(file).each_with_index do |line, i|
		logs.push(parser.parse(line)) 
	end 
	findErrors(logs)

end

def findErrors(logs)
	httpErrors = logs.select { |line|
				(399..500).cover?line["%>status"].to_i}
	printErrors("HTTP Error", httpErrors)

	nmapScans = logs.select { |line|
				line["%{User-Agent}i"].include? "Nmap" }  
	printErrors("Nmap Scan", nmapScans)

	shellCodes = logs.select { |line|
				line["%request"].include? "\\x" }
	printErrors("Shellcode", shellCodes) 	

end 

def printErrors(type, errors)
	errors.each do |e|
		printIncident(type, e["%source"], "HTTP", e["%request"], true)
	end 
end 
 
case ARGV.size 
when 0
	analyzePacketStream 
when 1 
	puts "Invalid Input. Usage: sudo ruby alarm.rb OR sudo ruby alarm.rb -r [INPUT_FILE]"
when 2 
	if ARGV[0] == "-r" 
		analyzeWebServerLog(ARGV[1]) 
	else
		puts "Invalid Input. Usage: sudo ruby alarm.rb -r [INPUT_FILE]" 
	end
else 
	puts "Invalid Input. Usage: sudo ruby alarm.rb OR sudo ruby alarm.rb -r [INPUT_FILE]"
end
 



# test packet to play with 
$config = PacketFu::Config.new(:iface => "eth0").config	
p = PacketFu::TCPPacket.new(:config => $config, :flavor => "Linux")

p.payload = "4117704037848040" 
p.tcp_flags.fin = 1
p.tcp_flags.psh = 0
p.tcp_flags.urg = 1
p.tcp_ecn = 0
p.tcp_win = 8192
p.tcp_hlen = 5
p.tcp_src = 5555
p.tcp_dst = 4444
p.recalc
p1 = p.to_s 




