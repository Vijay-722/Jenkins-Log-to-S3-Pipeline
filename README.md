
# Automated Jenkins Log Management System

![AWS](https://img.shields.io/badge/AWS-EC2%2C%20S3-orange)
![Jenkins](https://img.shields.io/badge/Jenkins-Automation-blue)
![Shell Script](https://img.shields.io/badge/Shell-Scripting-green)

## 📋 Project Overview

This project creates an automated system where Jenkins jobs are triggered when log files exceed 1GB in size. The system uploads logs to Amazon S3, clears the original files, and provides email notifications.

---

## 🎯 Objectives

1. Monitor log file sizes automatically.
2. Trigger Jenkins jobs when files exceed 1GB.
3. Upload logs to Amazon S3 securely.
4. Clear original files after successful upload.
5. Notify via email upon completion.
6. Maintain security and reliability.
---

## 📝 Prerequisites

**AWS Resources**
  - ✅ AWS Account with appropriate permissions.
  - ✅ EC2 Instance for Jenkins server.
  - ✅ EC2 Instance for monitoring server.
  - ✅ S3 Bucket for log storage.
  - ✅ IAM Roles with S3 access permissions.
---

## 1. AWS Setup

### 1.1 Create IAM Policies and Roles:

**Create S3 Bucket Policy:**

1. Go to IAM → Policies → Create Policy.
2. Choose Json.
3. Applied Policy:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-log-bucket-${AWS_ACCOUNT_ID}",
                "arn:aws:s3:::your-log-bucket-${AWS_ACCOUNT_ID}/*"
            ]
        }
    ]
}
```

4. Name: `S3-Log-Upload-Policy`

**Create EC2 Instance Role:**

1. IAM → Roles → Create Role.
2. Select "EC2" as trusted entity.
3. Attach policies: `AmazonS3FullAccess` (or custom policy above).
4. Name: `Jenkins-Server-Role`.

### 1.2 Create Security Groups

**Jenkins Server SG:**

 - Name: `jenkins-server-sg`
 - Inbound: SSH (22), HTTP (8080) from your IP
 - Outbound: All traffic

**Monitoring Server SG:**

 - Name: `monitoring-server-sg`
 - Inbound: SSH (22) from your IP
 - Outbound: All traffic

### 1.3 Launch EC2 Instances

**Jenkins Server:**

 - AMI: Ubuntu 22.04 LTS
 - Instance type: t2.medium
 - IAM role: `Jenkins-Server-Role`
 - Security group: `jenkins-server-sg`
 - Shell
 ```
apt-get update -y
apt-get install -y openjdk-11-jdk curl awscli
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | sudo tee \
  /usr/share/keyrings/jenkins-keyring.asc > /dev/null
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null
apt-get update -y
apt-get install -y jenkins
systemctl start jenkins
systemctl enable jenkins
usermod -aG sudo jenkins
```

**Monitoring Server:**

 - AMI: Amazon Linux 2023
 - Instance type: t2.micro
 - Security group: monitoring-server-sg
 - Shell
 ```
yum update -y
yum install -y httpd awscli curl
systemctl start httpd
systemctl enable httpd
mkdir -p /opt/scripts /var/log/log-monitor
```

### 1.4 Create S3 Bucket

1. Go to S3 → Create Bucket
2. Bucket name: `your-log-bucket-<your-account-id>`
3. Region: US East (N. Virginia) us-east-1
4. Object Ownership:
   - ACLs disabled
   - Select "Bucket owner enforced"
5. Block Public Access: ✓ Block all public access (checked).
6. Bucket Versioning: Enable.
7. Default encryption:
   - Enable
   - AWS Key Management Service key (SSE-KMS)
   - Choose AWS managed key (aws/s3)
---

## 2. Jenkins Setup

### 2.1 Get Initial Admin Password
```
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
sudo systemctl status jenkins
sudo systemctl start jenkins
sudo systemctl enable jenkins
sleep 30
sudo cat /var/lib/jenkins/secrets/initialAdminPassword
```

Copy the password - it will look something like:
`a7491d4bf91943de9a4e1a0184356c4c`

### 2.2 Access Jenkins in Browser

1. Open your web browser.
2. Go to: `http://<YOUR_JENKINS_SERVER_PUBLIC_IP>:8080`

### 2.3 Unlock Jenkins

1. Paste the password you copied.
2. Click "Continue"

### 2.4 Install Suggested Plugins

- Click "Install suggested plugins"

### 2.5 Create Admin User

Fill in the details:
 - Username: admin (recommended)
 - Password: [Create a strong password]
 - Confirm password: [Re-enter password]
 - Full name: Jenkins Administrator
 - Email address: your-email@example.com
 - Save and Continue

### 2.6 Install Additional Required Plugins
1. Open browser: `http://<jenkins-public-ip>:8080`
- AWS CLI
- Email Extension Plugin
- Pipeline

### 2.7 Configure AWS CLI on Jenkins Server
```
sudo -u jenkins aws configure
AWS Access Key ID [None]: YOUR_ACCESS_KEY
AWS Secret Access Key [None]: YOUR_SECRET_KEY
Default region name [None]: us-east-1
Default output format [None]: json
sudo -u jenkins aws sts get-caller-identity
# You should see output like:
# {
#     "UserId": "AROAABCDEFGHIJKLMNOPQ:i-0123456789abcdef0",
#     "Account": "123456789012",
#     "Arn": "arn:aws:sts::123456789012:assumed-role/Jenkins-Server-Role/i-0123456789abcdef0"
# }

# Test S3 access (replace with your actual bucket name)
sudo -u jenkins aws s3 ls s3://your-log-bucket-123456789012/
```

### 2.8 Create Jenkins API Token

1. Jenkins → Manage Jenkins → Manage Users → Configure.
2. Add new API token → Copy token.
---
## 3. Monitoring Script Setup

### 3.1 Create Monitoring Script
On monitoring server
```
sudo mkdir -p /opt/scripts
sudo nano /opt/scripts/monitor_log_size.sh
```

Paste the monitoring script content
```
LOG_FILE="/var/log/httpd/access_log"
SIZE_LIMIT_GB=1
SIZE_LIMIT_BYTES=$((SIZE_LIMIT_GB * 1024 * 1024 * 1024))
JENKINS_URL="http://<JENKINS_SERVER_IP>:8080"  # Replace with your Jenkins IP
JENKINS_JOB_NAME="log-file-to-s3"
JENKINS_USER="admin"
JENKINS_TOKEN="your_jenkins_api_token_here"    # Replace with your actual token
LOG_DIR="/var/log/log-monitor"
MONITOR_LOG="$LOG_DIR/monitor.log"

# Create log directory if it doesn't exist
sudo mkdir -p "$LOG_DIR"
sudo chmod 755 "$LOG_DIR"

# Logging function
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | sudo tee -a "$MONITOR_LOG"
}

# Error handling function
handle_error() {
    log_message "ERROR: $1"
    exit 1
}

# Check if log file exists, create if it doesn't
if [[ ! -f "$LOG_FILE" ]]; then
    sudo touch "$LOG_FILE"
    sudo chown apache:apache "$LOG_FILE" 2>/dev/null || sudo chown www-data:www-data "$LOG_FILE" 2>/dev/null
    sudo chmod 644 "$LOG_FILE"
    log_message "Created log file: $LOG_FILE"
fi

# Get current file size
FILE_SIZE=$(sudo stat -c%s "$LOG_FILE" 2>/dev/null) || handle_error "Failed to get file size for $LOG_FILE"

# Convert bytes to MB for logging
FILE_SIZE_MB=$((FILE_SIZE / 1024 / 1024))

log_message "Checking $LOG_FILE - Current size: ${FILE_SIZE_MB}MB / ${SIZE_LIMIT_GB}GB limit"

# Check if file size exceeds limit
if [[ $FILE_SIZE -gt $SIZE_LIMIT_BYTES ]]; then
    log_message "Log file size (${FILE_SIZE_MB}MB) exceeds limit (${SIZE_LIMIT_GB}GB). Triggering Jenkins job..."
    
    # URL encode the file path
    ENCODED_LOG_FILE=$(printf '%s' "$LOG_FILE" | jq -s -R -r @uri 2>/dev/null || echo "$LOG_FILE")
    
    # Trigger Jenkins job with file path as parameter
    RESPONSE=$(curl -s -w "%{http_code}" -X POST \
        -u "$JENKINS_USER:$JENKINS_TOKEN" \
        "$JENKINS_URL/job/$JENKINS_JOB_NAME/buildWithParameters?LOG_FILE_PATH=$ENCODED_LOG_FILE" \
        2>/dev/null)
    
    HTTP_STATUS=${RESPONSE: -3}
    RESPONSE_BODY=${RESPONSE%???}
    
    if [[ $HTTP_STATUS -eq 201 ]]; then
        log_message "Jenkins job triggered successfully. HTTP Status: $HTTP_STATUS"
    elif [[ $HTTP_STATUS -eq 200 ]]; then
        log_message "Jenkins job triggered successfully. HTTP Status: $HTTP_STATUS"
    else
        handle_error "Failed to trigger Jenkins job. HTTP Status: $HTTP_STATUS, Response: $RESPONSE_BODY"
    fi
else
    log_message "Log file size is within limits. No action required."
fi

log_message "Monitoring check completed."
```
Exit

### 3.2 Make Script Executable and Test
```
sudo chmod +x /opt/scripts/monitor_log_size.sh
sudo chown root:root /opt/scripts/monitor_log_size.sh

# Test the script
sudo /opt/scripts/monitor_log_size.sh
```

### 3.3 Set Up Cron Job
```
# Edit crontab as root
sudo crontab -e

# Add this line to run every 5 minutes
*/5 * * * * /opt/scripts/monitor_log_size.sh

# Verify cron job
sudo crontab -l
```
---
## 4. Jenkins Job Creation

### 4.1 Create Pipeline Job

1. Jenkins → New item → Pipeline → `log-file-to-s3`
2. Check "This project is parameterized"
3. Add String parameter: `LOG_FILE_PATH` with default `/var/log/httpd/access_log`

### 4.2 Pipeline Script
```
pipeline {
    agent any
    
    parameters {
        string(name: 'LOG_FILE_PATH', defaultValue: '/var/log/httpd/access_log', description: 'Path to the log file that was processed')
    }
    
    environment {
        AWS_REGION = 'us-east-1'
        S3_BUCKET = 'your-log-bucket-340752812821'
        RECIPIENT_EMAIL = 'devops@yourcompany.com'  // Change to your email
        BUILD_TIMESTAMP = sh(script: 'date "+%Y-%m-%d %H:%M:%S"', returnStdout: true).trim()
    }
    
    stages {
        stage('Notification Received') {
            steps {
                script {
                    echo "✅ Log file processing completed successfully by monitoring server"
                    echo "S3 Bucket: ${env.S3_BUCKET}"
                    echo "AWS Region: ${env.AWS_REGION}"
                    echo "Log file path: ${params.LOG_FILE_PATH}"
                    echo "Processing completed at: ${env.BUILD_TIMESTAMP}"
                }
            }
        }
        
        stage('Verify S3 Upload') {
            steps {
                script {
                    echo "Checking recent uploads to S3 bucket..."
                    
                    // Get recent S3 files for email content
                    env.S3_UPLOADS = sh(script: """
                        aws s3 ls s3://${env.S3_BUCKET}/access-logs/ --region ${env.AWS_REGION} | sort -r | head -5 || echo "No files found"
                    """, returnStdout: true).trim()
                    
                    echo "Recent S3 uploads:\n${env.S3_UPLOADS}"
                }
            }
        }
    }
    
    post {
        always {
            echo "Build completed: ${currentBuild.currentResult}"
            echo "Build URL: ${env.BUILD_URL}"
            
            // Email notification with rich HTML content
            emailext (
                subject: "Jenkins Build ${currentBuild.currentResult} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body { font-family: Arial, sans-serif; margin: 20px; }
                            .success { color: #2ecc71; }
                            .failure { color: #e74c3c; }
                            .info { color: #3498db; }
                            .container { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
                            .header { background-color: #f8f9fa; padding: 10px; border-radius: 3px; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h2>Log File Processing Notification</h2>
                            </div>
                            
                            <p><strong>Build Status:</strong> 
                                <span class="${currentBuild.currentResult == 'SUCCESS' ? 'success' : 'failure'}">
                                    ${currentBuild.currentResult}
                                </span>
                            </p>
                            
                            <p><strong>Job Name:</strong> ${env.JOB_NAME}</p>
                            <p><strong>Build Number:</strong> #${env.BUILD_NUMBER}</p>
                            <p><strong>Log File Processed:</strong> ${params.LOG_FILE_PATH}</p>
                            <p><strong>S3 Bucket:</strong> ${env.S3_BUCKET}</p>
                            <p><strong>AWS Region:</strong> ${env.AWS_REGION}</p>
                            <p><strong>Processing Time:</strong> ${env.BUILD_TIMESTAMP}</p>
                            
                            <p><strong>Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                            
                            <h3>Recent S3 Uploads:</h3>
                            <pre>${env.S3_UPLOADS}</pre>
                            
                            <hr>
                            <p class="info"><small>This is an automated message from Jenkins CI/CD system</small></p>
                        </div>
                    </body>
                    </html>
                """,
                to: "${env.RECIPIENT_EMAIL}",
                replyTo: "jenkins-noreply@yourcompany.com",
                mimeType: "text/html"
            )
        }
        
        success {
            echo "✅ SUCCESS: Monitoring server completed log file processing and upload to S3"
            
            // Additional success email with green theme
            emailext (
                subject: "SUCCESS: Log File Processed - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <div style="font-family: Arial, sans-serif; padding: 20px; border: 2px solid #2ecc71; border-radius: 5px;">
                        <h2 style="color: #2ecc71;">✅ Log File Processing Successful</h2>
                        <p>The log file has been successfully processed and uploaded to Amazon S3.</p>
                        
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 3px; margin: 10px 0;">
                            <strong>Details:</strong><br>
                            • <strong>Job:</strong> ${env.JOB_NAME}<br>
                            • <strong>Build:</strong> #${env.BUILD_NUMBER}<br>
                            • <strong>Log File:</strong> ${params.LOG_FILE_PATH}<br>
                            • <strong>S3 Bucket:</strong> ${env.S3_BUCKET}<br>
                            • <strong>Timestamp:</strong> ${env.BUILD_TIMESTAMP}
                        </div>
                        
                        <p>View build details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    </div>
                """,
                to: "${env.RECIPIENT_EMAIL}",
                mimeType: "text/html"
            )
        }
        
        failure {
            echo "❌ FAILURE: Notification processing failed"
            
            // Failure email with red theme
            emailext (
                subject: "FAILURE: Log Processing Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <div style="font-family: Arial, sans-serif; padding: 20px; border: 2px solid #e74c3c; border-radius: 5px;">
                        <h2 style="color: #e74c3c;">❌ Log File Processing Failed</h2>
                        <p>The log file processing job has failed. Please check the logs for details.</p>
                        
                        <div style="background-color: #fef2f2; padding: 15px; border-radius: 3px; margin: 10px 0;">
                            <strong>Error Details:</strong><br>
                            • <strong>Job:</strong> ${env.JOB_NAME}<br>
                            • <strong>Build:</strong> #${env.BUILD_NUMBER}<br>
                            • <strong>Log File:</strong> ${params.LOG_FILE_PATH}<br>
                            • <strong>Status:</strong> <span style="color: #e74c3c;">FAILED</span>
                        </div>
                        
                        <p><strong>Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        <p>Please check the build logs and monitoring server logs for error details.</p>
                    </div>
                """,
                to: "${env.RECIPIENT_EMAIL}",
                mimeType: "text/html"
            )
        }
    }
}
```
---
## 5. Testing the Complete Setup

### 5.1 Generate Test Log Data

On monitoring server:
```
#Create large log file for testing
sudo dd if=/dev/zero of=/var/log/httpd/access_log bs=1M count=1200
sudo chown apache:apache /var/log/httpd/access_log
```

### 5.2 Test Manual Trigger
```
#On monitoring server
sudo /apt/scripts/monitor_log_size.sh
```

### 5.3 Verify S3 Upload
```
ls s3://your-log-bucket-<account-id>/access-logs/
```
---
## 6. Email Notifications

### 6.1 Configure Jenkins Email
1. Go to Jenkins → Manage Jenkins → Configure System.
2. Email Notification Section:
   - SMTP server: `smtp.gmail.com`
   - SMTP port: 465
   - ✓ Use SMTP Authentication (CHECK this)
   - Username: your-email@gmail.com
   - Password: your-16-character-app-password (NOT your regular Gmail password)
   - Use SSL: ✓ (CHECK)
   - Use TLS: ✗ (UNCHECK)
Reply-To Address: your-email@gmail.com
3. Test the configuration:
    - Test e-mail recipient: your-email@gmail.com
    - Click "Test configuration"

**Verify Core Functionality is Working**
```
# On monitoring server, test the main workflow
sudo /opt/scripts/monitor_log_size.sh

# Check the log
sudo cat /var/log/log-monitor/monitor.log

# Verify S3 upload
aws s3 ls s3://your-log-bucket-340752812821/access-logs/
```

### 6.2 Update Pipeline with Email

1. Open Jenkins: `http://54.146.196.235:8080/`
2. Login with your admin credentials
3. Go to your job: `http://54.146.196.235:8080/job/log-file-to-s3/`
4. Click on "Configure"

**Update the Pipeline Script**

Replace the current pipeline script with this complete email-enabled version:

```
pipeline {
    agent any
    
    parameters {
        string(name: 'LOG_FILE_PATH', defaultValue: '/var/log/httpd/access_log', description: 'Path to the log file that was processed')
    }
    
    environment {
        AWS_REGION = 'us-east-1'
        S3_BUCKET = 'your-log-bucket-340752812821'
        RECIPIENT_EMAIL = 'devops@yourcompany.com'  // Change to your email
        BUILD_TIMESTAMP = sh(script: 'date "+%Y-%m-%d %H:%M:%S"', returnStdout: true).trim()
    }
    
    stages {
        stage('Notification Received') {
            steps {
                script {
                    echo "✅ Log file processing completed successfully by monitoring server"
                    echo "S3 Bucket: ${env.S3_BUCKET}"
                    echo "AWS Region: ${env.AWS_REGION}"
                    echo "Log file path: ${params.LOG_FILE_PATH}"
                    echo "Processing completed at: ${env.BUILD_TIMESTAMP}"
                }
            }
        }
        
        stage('Verify S3 Upload') {
            steps {
                script {
                    echo "Checking recent uploads to S3 bucket..."
                    
                    // Get recent S3 files for email content
                    env.S3_UPLOADS = sh(script: """
                        aws s3 ls s3://${env.S3_BUCKET}/access-logs/ --region ${env.AWS_REGION} | sort -r | head -5 || echo "No files found"
                    """, returnStdout: true).trim()
                    
                    echo "Recent S3 uploads:\n${env.S3_UPLOADS}"
                }
            }
        }
    }
    
    post {
        always {
            echo "Build completed: ${currentBuild.currentResult}"
            echo "Build URL: ${env.BUILD_URL}"
            
            // Email notification with rich HTML content
            emailext (
                subject: "Jenkins Build ${currentBuild.currentResult} - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <style>
                            body { font-family: Arial, sans-serif; margin: 20px; }
                            .success { color: #2ecc71; }
                            .failure { color: #e74c3c; }
                            .info { color: #3498db; }
                            .container { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
                            .header { background-color: #f8f9fa; padding: 10px; border-radius: 3px; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h2>Log File Processing Notification</h2>
                            </div>
                            
                            <p><strong>Build Status:</strong> 
                                <span class="${currentBuild.currentResult == 'SUCCESS' ? 'success' : 'failure'}">
                                    ${currentBuild.currentResult}
                                </span>
                            </p>
                            
                            <p><strong>Job Name:</strong> ${env.JOB_NAME}</p>
                            <p><strong>Build Number:</strong> #${env.BUILD_NUMBER}</p>
                            <p><strong>Log File Processed:</strong> ${params.LOG_FILE_PATH}</p>
                            <p><strong>S3 Bucket:</strong> ${env.S3_BUCKET}</p>
                            <p><strong>AWS Region:</strong> ${env.AWS_REGION}</p>
                            <p><strong>Processing Time:</strong> ${env.BUILD_TIMESTAMP}</p>
                            
                            <p><strong>Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                            
                            <h3>Recent S3 Uploads:</h3>
                            <pre>${env.S3_UPLOADS}</pre>
                            
                            <hr>
                            <p class="info"><small>This is an automated message from Jenkins CI/CD system</small></p>
                        </div>
                    </body>
                    </html>
                """,
                to: "${env.RECIPIENT_EMAIL}",
                replyTo: "jenkins-noreply@yourcompany.com",
                mimeType: "text/html"
            )
        }
        
        success {
            echo "✅ SUCCESS: Monitoring server completed log file processing and upload to S3"
            
            // Additional success email with green theme
            emailext (
                subject: "SUCCESS: Log File Processed - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <div style="font-family: Arial, sans-serif; padding: 20px; border: 2px solid #2ecc71; border-radius: 5px;">
                        <h2 style="color: #2ecc71;">✅ Log File Processing Successful</h2>
                        <p>The log file has been successfully processed and uploaded to Amazon S3.</p>
                        
                        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 3px; margin: 10px 0;">
                            <strong>Details:</strong><br>
                            • <strong>Job:</strong> ${env.JOB_NAME}<br>
                            • <strong>Build:</strong> #${env.BUILD_NUMBER}<br>
                            • <strong>Log File:</strong> ${params.LOG_FILE_PATH}<br>
                            • <strong>S3 Bucket:</strong> ${env.S3_BUCKET}<br>
                            • <strong>Timestamp:</strong> ${env.BUILD_TIMESTAMP}
                        </div>
                        
                        <p>View build details: <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                    </div>
                """,
                to: "${env.RECIPIENT_EMAIL}",
                mimeType: "text/html"
            )
        }
        
        failure {
            echo "❌ FAILURE: Notification processing failed"
            
            // Failure email with red theme
            emailext (
                subject: "FAILURE: Log Processing Failed - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <div style="font-family: Arial, sans-serif; padding: 20px; border: 2px solid #e74c3c; border-radius: 5px;">
                        <h2 style="color: #e74c3c;">❌ Log File Processing Failed</h2>
                        <p>The log file processing job has failed. Please check the logs for details.</p>
                        
                        <div style="background-color: #fef2f2; padding: 15px; border-radius: 3px; margin: 10px 0;">
                            <strong>Error Details:</strong><br>
                            • <strong>Job:</strong> ${env.JOB_NAME}<br>
                            • <strong>Build:</strong> #${env.BUILD_NUMBER}<br>
                            • <strong>Log File:</strong> ${params.LOG_FILE_PATH}<br>
                            • <strong>Status:</strong> <span style="color: #e74c3c;">FAILED</span>
                        </div>
                        
                        <p><strong>Build URL:</strong> <a href="${env.BUILD_URL}">${env.BUILD_URL}</a></p>
                        <p>Please check the build logs and monitoring server logs for error details.</p>
                    </div>
                """,
                to: "${env.RECIPIENT_EMAIL}",
                mimeType: "text/html"
            )
        }
    }
}
```
- Save.
- Verify the configuration was saved successfully.
-  test if AWS CLI is working on your Jenkins server:
```
sudo -u jenkins aws sts get-caller-identity
sudo -u jenkins aws s3 ls
```

### 6.3 Test the Pipeline
```
curl -X POST -u "admin:11dc5d4b9956e7d3c6c2b8e22e40d0d10d" \ http://54.146.196.235:8080/job/log-file-to-s3/build
```
---
## 7. Security Hardening

### 7.1 Secure Jenkins

#### Access Global Security Configuration
1. Go to Jenkins: `http://54.146.196.235:8080/`
2. Login with admin credentials.
3. Click: Manage Jenkins → Configure Global Security.

#### Enable Security Settings
- Configure these settings:
  - ✓ Enable security
  - Security Realm: "Jenkins' own user database"
  - ✓ Allow users to sign up (disable after creating users
  - Authorization: "Logged-in users can do anything" (start with this)
  - ✓ Prevent Cross Site Request Forgery exploits
  - ✓ Agent protocols: Enable only "JNLP4-connect" and "Ping"

#### Configure via config.xml
```
# Backup the config file first
sudo cp /var/lib/jenkins/config.xml /var/lib/jenkins/config.xml.backup.$(date +%Y%m%d)

# Edit the configuration
sudo nano /var/lib/jenkins/config.xml
```
### 7.2 Make Script Executable and Test
```
sudo chmod +x /opt/scripts/monitor_log_size.sh
sudo chown root:root /opt/scripts/monitor_log_size.sh
```
```
sudo corntab -e
sudo crontab -l
sudo dd if=/dev/urandom of=/var/log/httpd/access_log bs=1M count=1200
sudo chmod 644 /var/log/httpd/access_log
sudo ls -la /var/log/httpd/access_log
sudo du -h /var/log/httpd/access_log
sudo /apt/scripts/monitor_log_size.sh

aws s3 ls s3://your-log-bucket-340752812821/access-logs/

sudo cat /var/log/log-monitor/monitor.log | grep -i jenkins

curl -X POST -u "admin:11dc5d4b9956e7d3c6c2b8e22e40d0d10d" \ http://54.146.196.235:8080/job/log-file-to-s3/build
```
---
## 📧 Notifications
The system sends email notifications for:

  - ✅ Successful S3 uploads
  - ❌ Failed pipeline executions
  - ⚠️ Monitoring script errors
---

## 🔒 Security Considerations
  - IAM roles instead of access keys
  - Secure Jenkins API tokens
  - Regular log rotation
  - S3 bucket encryption enabled
  - Limited S3 bucket policies
  - Regular security updates

---
## ✅ Benefits

  - Automated log file monitoring and processing
  - Secure S3 storage with versioning
  - Flexible parameterized Jenkins pipeline
  - Reliable email notifications
  - Scalable architecture for multiple log sources
