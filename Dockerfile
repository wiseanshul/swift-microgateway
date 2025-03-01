# Use an official Tomcat base image with JDK 21
FROM tomcat:10.1-jdk21

# Set working directory inside the container
WORKDIR /usr/local/tomcat/webapps/

# Copy the WAR file to the Tomcat webapps directory and rename it to ROOT.war
COPY target/swift-microgateway-0.0.1-SNAPSHOT.war ROOT.war

# Ensure proper permissions (optional, for Linux-based environments)
RUN chown -R root:root /usr/local/tomcat/webapps/

# Expose the default Tomcat port
EXPOSE 8080

# Start Tomcat with proper signal handling
CMD ["catalina.sh", "run"]
