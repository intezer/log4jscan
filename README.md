# log4jscan for Linux

## Descrpition
Scan **Linux** hosts for **active usage** of log4j (log4j-core)
* Only running processes are scanned

### Provided info:
* PID
* Container ID (if relevant)
* Log4j version
* Jar path
* Indication if the jar contains the vulnerable Jndilookup class
* Process command line

## Usage
````
chmod +x ./log4jscan.sh
sudo ./log4jscan.sh
````

## How it works?
* log4jscan will go over all running processes, and will look for jar files opened by each process
* If the jar file itself is log4j-core-*.jar or if log4j is embedded into the application jar, it will look for the Jndilookup class inside the jar
  * Thanks @CyberRaiju for the inspiration https://twitter.com/CyberRaiju/status/1469505677580124160
* Additional process info is collected from procfs

## Containers
 * log4jscan provides the container ID of the process, more info about the container could be obtained using commands like `docker inspect {container_id}`
  
## Example
```` 
vagrant@ubuntu-bionic:~$ sudo ./log4jscan.sh 
Found a process using Log4j:
   PID: 22556
   Container ID: 73004f1018480283dc99ab7e1ed4de3d0d8a1d566d88089cca7ba79fb18c1f40
   Log4j version: 2.14.1
   Jar path: /app/spring-boot-application.jar (the path is relative to the container)
   Jar contains Jndilookup class: true
   Process command line: java -jar /app/spring-boot-application.jar 

Summary:
   Log4j was found during the scan, please follow the guidelines provided by The Apache Software Foundation at https://logging.apache.org/log4j/2.x/security.html 
   ````
