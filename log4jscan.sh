#!/bin/bash

###################################################################
#Script Name    : log4jscan                                                                                             
#Description    : Scan for log4j loaded into running processes
#Version        : 1.0.0
#License        : Apache License 2.0
#Args    	      : None                                                                                          
#Author       	: Doron Shem Tov (Intezer)                                                
#Email         	: support@intezer.com                                           
###################################################################


print_match_info() {
	pid=$1
	log4j_version=$2
	has_jndilookupclass=$3
	jar_path=$4
	container_id=$(grep -Po -m 1 "((.*/docker/\K.*)|(.*/k8s.io/\K.*))" /proc/${pid}/cgroup)
	echo "Found a process using Log4j:"
	echo "   PID: ${pid}"
	if [[ -n ${container_id} ]]; then
		echo "   Container ID: ${container_id}"
	fi
	echo "   Log4j version: ${log4j_version}"
	if [[ -n ${container_id} ]]; then
		echo "   Jar path: ${jar_path} (the path is relative to the container)"
	else
		echo "   Jar path: ${jar_path}"
	fi
	echo "   Jar contains Jndilookup class: ${has_jndilookupclass}"
	echo "   Process command line: $(tr "\000" " " < /proc/${pid}/cmdline)"
	echo ""
}

main() {
	found_log4j=false
	matched_files=()
	# go over all running processes with loaded jar files
	find /proc/*/fd/ -type l | while read line; do
       		# resolve the file descriptor target
		link_target=$(readlink ${line})

		# skip non jar files
       		if [[ "$link_target" != *.jar ]]; then
			continue
		fi

		# resolve an absulte path via procfs to support containerized processes
        	proc_base=${line%/*/*}
		pid=${proc_base##*/}
    		abs_path=$proc_base/root$link_target


		if [[ "$abs_path" =~ log4j-core.*jar ]]; then
                	# log4j-core is loaded
			found_log4j=true
                	log4j_jar_name=${abs_path%.*}
			log4j_version=${log4j_jar_name##*-*-}
		else
			log4j_match=$(grep -aio -m 1 "log4j-core.*jar" ${abs_path})
			# skip files without log4j
			if [[ -z "$log4j_match" ]]; then
				continue
			else
				found_log4j=true
        			log4j_jar_name=${log4j_match%.*}
        			log4j_version=${log4j_jar_name##*-*-}
			fi
		fi

		# skip files we already found
		if [[ ${matched_files[@]} =~ $abs_path ]]; then
			continue
		else
			matched_files+=($abs_path)
		fi
	
		# look for vulnerable JndiLooup class inside the jar
		# thanks @CyberRaiju for the inspiration https://twitter.com/CyberRaiju/status/1469505677580124160
		if grep -q -l -r -m 1 JndiLookup.class $abs_path; then
			has_jndilookupclass=true
		else
			has_jndilookupclass=false
		fi
	
		print_match_info $pid $log4j_version $has_jndilookupclass $link_target
	done

	echo "Summary:"
	if [[ ! found_log4j ]]; then
		echo "   Log4j wan not found in the currently running processes."
		echo "   Since it is possible that Log4j is installed but not being used at the moment, it is recommended to check if Log4j is installed using your package manger (e.g. apt)"
		echo "   Follow the guidelines provided by The Apache Software Foundation at https://logging.apache.org/log4j/2.x/security.html"
	else
		echo "   Log4j was found during the scan, please follow the guidelines provided by The Apache Software Foundation at https://logging.apache.org/log4j/2.x/security.html"
	fi
}

main
