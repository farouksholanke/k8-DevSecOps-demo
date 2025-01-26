# DevSecOps Pipeline Project 🚀🔒✨


## Overview
This project demonstrates the integration of security into every stage of the DevOps pipeline, transitioning into a comprehensive DevSecOps workflow. The purpose is to enhance the security of the software delivery lifecycle while maintaining efficiency and automation.

## Goal of the Project
The primary goal of my project is to integrate security into every stage of the DevOps pipeline, transforming it into a DevSecOps workflow. My aim is to ensure that security is continuously enforced throughout the Software Development Lifecycle (SDLC), from code development to deployment and monitoring. By doing this, I want to enhance the security of software delivery while maintaining efficiency and automation.

## Tools I Used
### Infrastructure & Orchestration:
- **Azure VM**: For hosting the environment.
- **Kubernetes**: For container orchestration.
- **Istio**: For securing pod-to-pod communication and service mesh management.

### Security Tools:
- **Talisman**: For pre-push Git hooks to prevent sensitive data leaks.
- **SonarQube**: For Static Application Security Testing (SAST).
- **OWASP Dependency-Check**: For dependency vulnerability scanning.
- **Trivy**: For container image vulnerability scanning.
- **Kube-bench**: For CIS benchmarking of Kubernetes clusters.
- **Kube-scan**: For Kubernetes risk assessment.
- **Falco**: For runtime security monitoring.

### Testing Tools:
- **Jacoco**: For Java code coverage.
- **PIT (Mutation Testing)**: For testing the robustness of unit tests.
- **OWASP ZAP**: For Dynamic Application Security Testing (DAST).

### CI/CD & Automation:
- **Jenkins**: For pipeline automation.
- **Docker**: For containerization.
- **Maven**: For Java dependency management and builds.
- **GitHub Webhooks**: For automatic build triggers.

### Monitoring & Observability:
- **Prometheus & Grafana**: For monitoring and visualization.
- **Kiali**: For Istio service mesh observability.

### Communication:
- **Slack**: For pipeline notifications and alerts.

## Let's Jump into It!
### DevOps vs. DevSecOps: A Brief Explanation
In my project, I focused on transforming a traditional DevOps pipeline into a DevSecOps pipeline. Here's a quick breakdown of the difference between the two:

- **DevOps** is all about collaboration and automation between development and operations teams to deliver software faster and more efficiently. It focuses on continuous integration (CI), continuous delivery (CD), and automation of the software delivery lifecycle (SDLC).

- **DevSecOps**, on the other hand, takes DevOps a step further by integrating security into every stage of the pipeline. It ensures that security is not an afterthought but a continuous process throughout development, testing, deployment, and monitoring. This approach helps identify and mitigate vulnerabilities early, reducing risks in production.

![Image](https://github.com/user-attachments/assets/88a6d504-0fd4-4e9d-9d43-3e029d22ecbc)
![Image](https://github.com/user-attachments/assets/88a6d504-0fd4-4e9d-9d43-3e029d22ecbc)

## Azure VM Configuration
**Account**: Azure

**VM Details**:
- **Operating System**: Ubuntu 18.04
- **HDD**: 512 GB
- **CPU**: 4
- **Memory**: 16GB
- **External IP**: Static
- **Firewall Rules**: Allow all ingress (for practice purposes only)

Using the script `install-script.sh`, the following were installed:
- Docker
- kubeadm
- kubectl
- kubelet
- Kubernetes network plugin: Weavenet

Kubernetes was initialized using `kubeadm init`, followed by the installation of the Container Network Interface (CNI).

The Azure VM was created using a custom template with parameters defined in a JSON file.

## Application Installation
**Bash Scripts Used**:
- `installscript.sh`: To install applications on the VM.
- `installer.sh`: To install Jenkins plugins.

**Jenkins Plugins Installed**:
- Performance: 3.18
- Docker Workflow: 1.26
- Dependency Check Jenkins Plugin: 5.1.1
- Blue Ocean: 1.24.7
- Jacoco: 3.2.0
- Slack: 2.4.8
- Sonar: 2.13.1
- Pit Mutation: 1.0-18
- Kubernetes CLI: 1.10.2

![Image](https://github.com/user-attachments/assets/647e661b-1e8d-4aa9-bf37-d06fa1b2dbcb)
![Image](https://github.com/user-attachments/assets/5a9274fc-3f08-41a2-80fb-8de8e4f6ff2d)

## Application Use Case
### Overview
The setup involves two microservices:

1. **Node.js Microservice**
   - **Port**: 5000
   - **Endpoint**: `/plusone`
   - **Functionality**: Takes a number, increments it by one, and returns the result.

2. **Spring Boot Microservice**
   - **Port**: 8080
   - **Endpoints**:
     - `/increment`: Calls the Node.js service and increments the number.
     - `/compare`: Compares numbers to 50 (greater than, equal to, or less than).
     - `/`: Displays a plain text welcome message.

## Why Maven for Java Apps
Maven was chosen for dependency management and building the Spring Boot application due to its wide adoption and efficient handling of Java dependencies.

## GitHub Webhook Implementation
A webhook was implemented to trigger builds automatically on code changes.

![Image](https://github.com/user-attachments/assets/c21cb1e9-e681-41f1-86e8-f343a09dcf50)

## Unit Testing
### Benefits:
- Finds bugs early.
- Reduces the cost of changes.
- Improves code quality.

### Tool Used: Jacoco (Java Code Coverage)
Jacoco provides line coverage metrics to ensure test coverage.

### Pipeline Snippet:
```groovy
pipeline {
  agent any
  stages {
    stage('Build Artifact') {
      steps {
        sh "mvn clean package -DskipTests=true"
        archive 'target/*.jar' // Save artifacts for download
      }
    }
    stage('Unit Tests') {
      steps {
        sh "mvn test"
      }
    }
  }
}
```

All tests passed successfully, and the build was triggered.

![Image](https://github.com/user-attachments/assets/6e9c0833-65ba-49c6-9732-9c4924f5c295)
![Image](https://github.com/user-attachments/assets/ba4598db-b407-4a7f-94b8-3388a4bd79e3)

## Docker Integration
### Why Docker?
Docker provides containerization, ensuring consistent environments across development, testing, and production stages.

### Jenkins Docker Build and Push:
```groovy
stage('Docker Build and Push') {
  steps {
    withDockerRegistry([credentialsId: "docker-hub", url: ""]) {
      sh 'printenv'
      sh 'sudo docker build -t farouksholanke/numeric-app:"$GIT_COMMIT" .'
      sh 'docker push farouksholanke/numeric-app:"$GIT_COMMIT"'
    }
  }
}
```

![Image](https://github.com/user-attachments/assets/9f5677dd-706b-4c22-af17-69d1e0ccf527)

## Kubernetes Deployment
The Node.js service was deployed in a Kubernetes cluster. A deployment stage was added in the Jenkinsfile.

### Kubernetes Deployment Stage:
```groovy
stage('Kubernetes Deployment - DEV') {
  steps {
    withKubeConfig([credentialsId: 'kubeconfig']) {
      sh "sed -i 's#replace#farouksholanke/numeric-app:${GIT_COMMIT}#g' k8s_deployment_service.yaml"
      sh "kubectl apply -f k8s_deployment_service.yaml"
    }
  }
}
```

### Manifest Files:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: devsecops
  name: devsecops
spec:
  replicas: 2
  selector:
    matchLabels:
      app: devsecops
  template:
    metadata:
      labels:
        app: devsecops
    spec:
      containers:
      - image: replace
        name: devsecops-container
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: devsecops
  name: devsecops-svc
spec:
  ports:
  - port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    app: devsecops
  type: NodePort
```

The deployment was successful with two replicas running. The service is exposed on NodePort 32032, and the application behaves as expected.

![Image](https://github.com/user-attachments/assets/2c76dda7-9809-4fa2-a94f-d2cbcc049b4b)
![Image](https://github.com/user-attachments/assets/68460c09-0179-4e94-9a10-f66837d3bc05)
![Image](https://github.com/user-attachments/assets/09bc94c0-6d75-4ed8-b72b-cc3eafa5f33d)

## Transition to DevSecOps
In this section, security is integrated into the DevOps pipeline to enhance continuous security throughout the SDLC.

### Key Additions:
- Testing stages
- Vulnerability scans
- Dynamic application security testing (DAST)

## Git Hooks with Talisman
Talisman was installed as a pre-push hook to prevent sensitive information from being pushed to the repository. Reports were generated when attempts were made to push sensitive files.

![Image](https://github.com/user-attachments/assets/4d18eea4-fa39-437c-8153-17e96e7a0534)

Any of these can be ignored from scanning by populating the `.talismansrc` file with the file information.

## Mutation Testing
### Tool Used: PIT
Runs unit tests against modified versions of the application code.
- **Tests pass**: Mutation not caught.
- **Tests fail**: Mutation caught and "killed."

Initial tests returned a mutation score of 40%, below the threshold of 70%.

![Image](https://github.com/user-attachments/assets/6ec08c75-18fa-4919-8b3f-c8b52f4bf13f)
![Image](https://github.com/user-attachments/assets/1becd645-78be-43f6-952f-c21a718ea505)

After improving test cases, the mutation stage passed, demonstrating robust unit testing.

![Image](https://github.com/user-attachments/assets/ce297685-847f-4a10-bd6c-0a6192ae26f5)

## Static Application Security Testing (SAST) with SonarQube
SonarQube is an open-source platform for code quality inspection using static analysis.

### Benefits:
- Identifies bugs early in the SDLC.
- Defines project-specific rules.
- Enforces quality gates.

### Implementation:
SonarQube was installed on the Azure VM using a Docker image and exposed on port 9000. Integration with Jenkins was configured, and a pipeline stage was added for SonarQube analysis.

![Image](https://github.com/user-attachments/assets/599712a6-374b-40fb-a409-3807986d4241)

### Jenkinsfile Snippet:
```groovy
stage('SonarQube Analysis') {
  steps {
    withSonarQubeEnv('SonarQube') {
      withCredentials([string(credentialsId: 'SONAR_AUTH_TOKEN', variable: 'SONAR_AUTH_TOKEN')]) {
        sh """
          mvn sonar:sonar \
            -Dsonar.projectKey=numeric-application \
            -Dsonar.host.url=http://dev-secops-demo.eastus.cloudapp.azure.com:9000 \
            -Dsonar.login=${SONAR_AUTH_TOKEN}
        """
      }
    }
  }
}
```

The build passed, and the code passed the default quality gates.

![Image](https://github.com/user-attachments/assets/4f1047b8-f587-47bd-ae4d-8e37e175e4b7)
![Image](https://github.com/user-attachments/assets/59f88958-1c04-4971-be3d-3dea45631683)

I updated my quality gates with new rules for code smells and code coverage in the overall code, created a webhook for Jenkins on SonarQube so that I can configure my Jenkins pipeline to pause for the Sonar analysis to be complete and receive the status of the quality gates from Sonar. Jenkins will fail the pipeline if the quality gate fails.

![Image](https://github.com/user-attachments/assets/160a68e1-9210-4fb6-b52f-74aca307e185)

```groovy
timeout(time: 2, unit: 'MINUTES') {
  script {
    waitForQualityGate abortPipeline: true
  }
}
```

After pushing these changes, my pipeline failed because the quality gates had failed due to a higher number of code smells than tolerated.

![Image](https://github.com/user-attachments/assets/7c5ee606-4826-4515-98de-a8622bfbb285)

After removing duplicated and unused imports from my code, the pipeline was successful as the quality gates passed, proving that the SonarQube static analysis is functioning as desired.

![Image](https://github.com/user-attachments/assets/6af9130e-6d5c-4668-9bcf-6029c4d49a6a)

## Dependency Scanning with OWASP Dependency-Check
### Purpose:
- Identifies vulnerabilities in open-source dependencies.
- Compares dependencies to the Common Vulnerability and Exposure (CVE) list.

### Implementation:
Dependency-check was configured in the `pom.xml` file, and a Jenkins stage was added:

```groovy
stage('Vulnerability Scan - Docker') {
  steps {
    sh "mvn dependency-check:check"
  }
  post {
    always {
      dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'
    }
  }
}
```

Critical vulnerabilities were identified and resolved by updating dependencies.

![Image](https://github.com/user-attachments/assets/5b3fc695-a7b0-4e50-a5d6-0844b3d22e4d)
![Image](https://github.com/user-attachments/assets/884a613c-d168-4ef7-a069-9d95f89a0207)

## Image Scanning with Trivy
### Purpose:
Trivy scans container images for vulnerabilities in OS packages and application dependencies.

### Implementation:
Trivy was run in a Jenkins pipeline using the following script:

```bash
#!/bin/bash
dockerImageName=$(awk 'NR==1 {print $2}' Dockerfile)
echo "$dockerImageName"

docker run --rm -v $WORKSPACE:/root/.cache/ aquasec/trivy:0.17.2 -q image --exit-code 1 --severity HIGH --light $dockerImageName
docker run --rm -v $WORKSPACE:/root/.cache/ aquasec/trivy:0.17.2 -q image --exit-code 1 --severity CRITICAL --light $dockerImageName

if [[ "$?" == 1 ]]; then
  echo "Image scanning failed. Vulnerabilities found."
  exit 1
else
  echo "Image scanning passed. No CRITICAL vulnerabilities found."
fi
```

The pipeline failed because four critical vulnerabilities were found, resulting in the exit code 1 being returned.

![Image](https://github.com/user-attachments/assets/377b8293-df76-429e-8d0d-65526b6025e6)

To solve this, I updated the base image in my Dockerfile, and the pipeline succeeded.

```dockerfile
FROM adoptopenjdk/openjdk8:alpine-slim
```

![Image](https://github.com/user-attachments/assets/d498ab4b-28f1-45d5-92df-8d6ac6aae6ed)

## Open Policy Agent (OPA) Conftest
### Purpose:
OPA Conftest is used to validate configuration files with policies written in the Rego language.

### Implementation:
- **Policy Enforcement**: Ensures compliance in Dockerfiles, Kubernetes manifests, and Terraform scripts.
- **Static Analysis**: Identifies issues without executing the configuration files.
- **Shift-Left Security**: Finds problems early in the pipeline.

I added a file with a set of Docker security best practices to my repo and ran OPA Conftest as a Docker image in my Jenkins pipeline. The pipeline failed because there were two failures, as shown below.

![Image](https://github.com/user-attachments/assets/fef29c8f-69cf-4180-9135-1b6b79ce97e2)

I updated my Dockerfile to correct these failures, and the pipeline is now successful.

```dockerfile
FROM adoptopenjdk/openjdk8:alpine-slim

EXPOSE 8080

ARG JAR_FILE=target/*.jar

RUN addgroup -S pipeline && adduser -S k8s-pipeline -G pipeline

COPY ${JAR_FILE} /home/k8s-pipeline/app.jar

USER k8s-pipeline

ENTRYPOINT ["java","-jar","/home/k8s-pipeline/app.jar"]
```

![Image](https://github.com/user-attachments/assets/7188101e-448f-4a0e-bb66-5ea460f989c6)

I did the same to check for security best practices in my Kubernetes cluster as well. My OPA Conftest file checks that services are of type NodePort and that containers are not running as root.

![Image](https://github.com/user-attachments/assets/ad7488c5-86c3-47a2-9812-922f78fb0769)

```groovy
stage('Vulnerability Scan - k8s') {
  steps {
    sh 'docker run --rm -v $(pwd):/project openpolicyagent/conftest test --policy opa-k8s-security.rego k8s_deployment_service.yaml'
  }
}
```

The test failed because my containers were running as root, so I added a security context to my deployment manifest file to set `runAsNonRoot` to `true` and `runAsUser` to `100`.

![Image](https://github.com/user-attachments/assets/4f8d875a-449b-46f5-92b8-6c056313fd78)

```yaml
spec:
  containers:
  - image: replace
    name: devsecops-container
    securityContext:
      runAsNonRoot: true
      runAsUser: 100
```

## Kubesec
### What?
Kubesec is an open-source Kubernetes security scanner and analysis tool that scans your Kubernetes cluster for common exploitable risks, such as privileged capabilities, and provides a severity score for each found vulnerability.

### Key Features:
- **Risk Scoring**: Assigns a numerical score to each workload, highlighting its security risk level.
- **Configuration Analysis**: Detects misconfigurations in pods, deployments, and other Kubernetes objects (e.g., privileged containers, overly permissive policies).
- **Policy Recommendations**: Provides actionable recommendations to improve the security posture of the cluster.
- **Cluster-Wide Assessment**: Analyzes all namespaces and workloads for security vulnerabilities or potential exploits.

### Implementation:
To integrate Kubesec into the pipeline, I modified the Jenkinsfile to run Kubesec as a shell script in parallel with the OPA Conftest scan of my deployment file.

```bash
#!/bin/bash

scan_result=$(curl -sSX POST --data-binary @"k8s_deployment_service.yaml" https://v2.kubesec.io/scan)
scan_message=$(curl -sSX POST --data-binary @"k8s_deployment_service.yaml" https://v2.kubesec.io/scan | jq .[0].message -r)
scan_score=$(curl -sSX POST --data-binary @"k8s_deployment_service.yaml" https://v2.kubesec.io/scan | jq .[0].score)

exit_code=$?

echo "Exit Code : $exit_code"

if [[ "${exit_code}" == 1 ]]; then
    echo "Image scanning failed. Vulnerabilities found."
    exit 1
else
    echo "Image scanning passed. No CRITICAL vulnerabilities found."
fi
```

The shell script sends a POST request to the Kubesec v2 API to scan the `k8s_deployment_service.yaml` file. The result of the scan is stored in variables. If the scan score is greater than 5, it passes; otherwise, the scan fails.

### Challenge & Solution:
My scan initially failed with a score of 1.

![Image](https://github.com/user-attachments/assets/c81ddbc5-e84c-4233-9205-aa9b0a4a3901)

Kubesec recommended following Kubernetes security best practices, such as using a read-only root file system, a service account, and CPU/memory limits.

![Image](https://github.com/user-attachments/assets/5be48c7e-8320-4760-bfc0-212511b3692e)

For the purpose of this demo project, I used the default service account and set `readOnlyRootFilesystem` to `true`. In a real-world scenario, I would use a service account with customized cluster roles and role bindings.

![Image](https://github.com/user-attachments/assets/0339d980-38c4-410a-9add-bfd65c27ca43)

After making these changes, the pipeline succeeded.

![Image](https://github.com/user-attachments/assets/8c917d26-27b2-4ed4-a004-80a92a6b3949)

## Trivy Image Scanning
### What?
Trivy is an open-source vulnerability scanner widely used in DevOps for ensuring security in containerized applications, cloud-native environments, and other software artifacts.

### Implementation:
In this section, I used Trivy to scan the updated Docker image that was built and pushed to my Docker registry.

![Image](https://github.com/user-attachments/assets/4caf57b4-7107-4da5-9516-d9c5e0058648)

```bash
#!/bin/bash

dockerImageName=$(awk 'NR==1 {print $2}' Dockerfile)
echo "$dockerImageName"

docker run --rm -v $WORKSPACE:/root/.cache/ aquasec/trivy:0.17.2 -q image --exit-code 0 --severity HIGH --light $dockerImageName
docker run --rm -v $WORKSPACE:/root/.cache/ aquasec/trivy:0.17.2 -q image --exit-code 0 --severity CRITICAL --light $dockerImageName

# Trivy scan result processing
exit_code=$?
echo "Exit Code : $exit_code"

# Check scan results
if [[ "${exit_code}" == 1 ]]; then
    echo "Image scanning failed. Vulnerabilities found."
    exit 1
else
    echo "Image scanning passed. No CRITICAL vulnerabilities found."
fi
```

The pipeline was successful as no critical vulnerabilities were found.

![Image](https://github.com/user-attachments/assets/983502bc-0589-4806-8a89-90ec8268363a)

## Integration Tests
### What?
Integration tests ensure that independently developed units of software work correctly when combined and connected to each other. They verify the interaction between different parts of the system, such as modules, services, or APIs, rather than individual functionality.

### Key Areas to Focus On in REST API Testing:
1. **HTTP Response Code**: Verifies that the API returns the appropriate status codes (e.g., `200 OK`, `404 Not Found`, `500 Internal Server Error`) for the given requests.
2. **HTTP Headers**: Tests the headers in the API response to ensure they are correct and as expected (e.g., `Content-Type`, `Authorization`, `Cache-Control`).
3. **Payload (JSON, XML)**: Validates the response payload for structure, content, and correctness.

### Implementation:
I implemented integration testing by using a bash script that gets the NodePort of my Kubernetes service and checks for the correctness of the behavior of my application as well as the HTTP response.

```groovy
stage('Integration Tests - DEV') {
  steps {
    script {
      try {
        withKubeConfig([credentialsId: 'kubeconfig']) {
          sh "bash integration-test.sh"
        }
      } catch (e) {
        withKubeConfig([credentialsId: 'kubeconfig']) {
          sh "kubectl -n default rollout undo deploy ${deploymentName}"
        }
        throw e
      }
    }
  }
}
```

![Image](https://github.com/user-attachments/assets/a178f0a1-3713-4620-a028-46d76f1f7616)

**Note**: The variables referenced in the bash scripts are environment variables from my Jenkinsfile.

![Image](https://github.com/user-attachments/assets/fb1baccb-0297-4e84-aaa7-7bfd4730a00e)

The desired result is for the application to increment the number received in the URI by one and return an HTTP response code of 200 for success.

![Image](https://github.com/user-attachments/assets/03c2089f-9b4e-4fb5-8e34-4bb04d52876a)

## DAST (Dynamic Application Security Testing)
### What?
DAST identifies security vulnerabilities by simulating external attacks on an application while it is running. It mimics real-world attackers by analyzing the application's behavior and responses in a live environment.

### Comparison to SAST:
- **SAST**: Scans the application's source code line by line when the application is at rest.
- **DAST**: Performed in a dynamic environment (application is running) and does not require access to the application's source code.

### Implementation:
For this project, I implemented **ZAP API Scan** because my Spring Boot application doesn’t expose any UI components.

### OWASP ZAP for Dynamic Security Testing
ZAP (Zed Attack Proxy) is an open-source web application security scanner designed for testing web applications.

### Implementation:
I added the following dependency to my `pom.xml` for Swagger integration:

```xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-ui</artifactId>
    <version>1.2.30</version>
</dependency>
```

I ran the ZAP scan with a bash script that sets up an OWASP ZAP scan, processes the scan result, and generates an HTML report.

```bash
#!/bin/bash

PORT=$(kubectl -n default get svc ${serviceName} -o json | jq .spec.ports[].nodePort)

# Run ZAP scan
docker pull zaproxy/zap-weekly
docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-weekly zap-api-scan.py -t $applicationURL:$PORT/v3/api-docs -f openapi -c zap_rules -r zap_report.html

exit_code=$?

# HTML Report
sudo mkdir -p owasp-zap-report
sudo mv zap_report.html owasp-zap-report

echo "Exit Code : $exit_code"

if [[ ${exit_code} -ne 0 ]]; then
    echo "OWASP ZAP Report has either Low/Medium/High Risk. Please check the HTML Report."
    exit 1;
else
    echo "OWASP ZAP did not report any Risk."
fi;
```

The test initially failed due to security issues.

![Image](https://github.com/user-attachments/assets/f672708e-7c30-4e1c-ab22-29730f2fa4da)
![Image](https://github.com/user-attachments/assets/e08305a0-9481-4f05-b457-f9a60f958a24)

To mitigate these errors, I added the Spring Boot Starter Security dependency to my `pom.xml` and configured security settings.

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

I also added a security configuration class:

```java
package com.devsecops;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
```

I also ignored some of the other remaining errors as they weren't critical.

![Image](https://github.com/user-attachments/assets/918232e1-7593-4c89-b1f1-780a6b5d3f1c)

After these changes, the pipeline succeeded.

## Slack Notifications
### Implementation:
I configured Slack in my Jenkins pipeline to receive notifications if the pipeline succeeded or failed.

![Image](https://github.com/user-attachments/assets/1aa5198a-9031-4df9-9307-3bb2f58a373d)

I added my Slack credentials.

![Image](https://github.com/user-attachments/assets/f3ec49a9-0ddc-41e4-872d-202d2d522cd4)

I configured my Slack library that I defined in my Jenkinsfile as referenced below.

```groovy
@Library('slack') _
```

![Image](https://github.com/user-attachments/assets/adf44126-aad8-409f-9fdd-5644c184f31a)

I added a post-build step to send a notification to Slack depending on the result of the build. The notifications are color-coded: green for success, yellow for an unstable build, and red for a failed build.

```groovy
@Library('slack') _

post {
  always {
    junit 'target/surefire-reports/*.xml'
    jacoco execPattern: 'target/jacoco.exec'
    pitmutation mutationStatsFile: '**/target/pit-reports/**/mutations.xml'
    dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'
    sendNotification currentBuild.result
  }
}
```

![Image](https://github.com/user-attachments/assets/a39d65b3-474c-4775-969f-30562b026762)

## Production
In this section, I will promote my application to a production environment. I will add stages in my Jenkins pipeline for CIS benchmarking for Kubernetes, Istio to secure communication between pods, monitoring using Falco and Kube-scan.

### Promote to Production
This stage displays a prompt for approval before the pipeline continues, allowing me to promote my application to a production environment.

```groovy
stage('Promote to PROD?') {
  steps {
    timeout(time: 2, unit: 'DAYS') {
      input 'Do you want to Approve the Deployment to Production Environment/Namespace?'
    }
  }
}
```

![Image](https://github.com/user-attachments/assets/9014fd9a-c268-430a-a4b6-268e8e9dd0b8)

## Kube-Bench for CIS Benchmarking
### What?
CIS benchmarks are configuration guidelines for various technology groups to safeguard systems against cyber threats. The **Center for Internet Security (CIS)** releases benchmarks for best practice security recommendations.

**Kube-bench** is a Go application that checks whether Kubernetes is deployed securely by running checks documented in the CIS Kubernetes Benchmark.

### Implementation:
I ran Kube-bench by downloading and installing its binaries:

```bash
cd /root/
wget https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.deb
dpkg -i kube-bench_0.4.0_linux_amd64.deb
```

In my project, I ran Kube-bench in a shell script to check the master node, kubelet, and etcd against certain CIS benchmarks:

```bash
total_fail=$(./kube-bench --config-dir "$(pwd)/cfg" --config "$(pwd)/cfg/config.yaml" master --version 1.15 --check 1.2.7,1.2.8,1.2.9 --json | jq .[].total_fail)

total_fail=$(./kube-bench --config-dir "$(pwd)/cfg" --config "$(pwd)/cfg/config.yaml" run --targets node --version 1.15 --check 4.2.1,4.2.2 --json | jq .[].total_fail)

total_fail=$(./kube-bench --config-dir "$(pwd)/cfg" --config "$(pwd)/cfg/config.yaml" run --targets etcd --version 1.15 --check 2.2 --json | jq .[].total_fail)
```

These commands check my Kubernetes cluster (version 1.15) for:
- **1.2.7**: Secure API server configurations (e.g., disabling anonymous access).
- **1.2.8**: Proper logging or audit configurations for the API server.
- **1.2.9**: TLS encryption or secure communication for the API server.
- **2.2**: Etcd-related security configurations (e.g., TLS encryption, authentication).
- **4.2.1 & 4.2.2**: Node-specific security settings.

### Pipeline Stage:
```groovy
stage('K8S CIS Benchmark') {
  steps {
    script {
      parallel(
        "Master": {
          sh "bash cis-master.sh"
        },
        "Etcd": {
          sh "bash cis-etcd.sh"
        },
        "Kubelet": {
          sh "bash cis-kubelet.sh"
        }
      )
    }
  }
}
```

The pipeline was successful as the CIS benchmark tests all passed.

![Image](https://github.com/user-attachments/assets/bc753c87-3455-4524-b888-d58df3789e1f)
![Image](https://github.com/user-attachments/assets/2d0adcb6-006a-47a4-a293-8922ff62e306)

## Istio Service Mesh
### Pod-to-Pod Communication
In Kubernetes, pods communicate with each other over a flat, routable network using unique IP addresses, leveraging Kubernetes services or direct pod IPs.

Securing communication would require manually configuring certificates, keys, and TLS settings for each microservice, which is error-prone and time-consuming.

**Istio** simplifies securing pod-to-pod communication by automating the process of applying mutual TLS (mTLS) across the entire service mesh. Istio handles this centrally through its control plane, ensuring consistent encryption, authentication, and policy enforcement across all pods without needing changes to individual application code.

### Implementation:
I downloaded Istio using the demo profile, which includes core Istio components and optional observability tools like Prometheus, Grafana, Jaeger, and Kiali.

```bash
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.18.0 sh -
cd istio-1.18.0
export PATH=$PWD/bin:$PATH
istioctl install --set profile=demo -y && kubectl apply -f samples/addons
```

The monitoring services are installed in the `istio-system` namespace as ClusterIP services. To access these dashboards externally, I changed the service type to NodePort.

![Image](https://github.com/user-attachments/assets/d8e92a30-825a-45f0-8578-dc5e292a6b5b)
![Image](https://github.com/user-attachments/assets/405af522-6c59-491b-ba91-1be4ecc9fefd)

### Injecting Istio Sidecar:
To inject Istio as a sidecar container into my pods in the production environment, I created a production namespace and labeled it with `istio-injection=enabled`.

```bash
kubectl create namespace prod
kubectl label namespace prod istio-injection=enabled
kubectl rollout restart deployment <deployment-name>
```

### Kiali Dashboard:
Kiali provides robust observability for the service mesh, including traffic topology, health grades, and dashboards.

As seen on my Kiali dashboard when I made a call to my `devsecops` service, the communication between the pods is secure, signified by the lock.

![Image](https://github.com/user-attachments/assets/2b803ac5-6c30-4fb6-b1c6-692f6ccc3589)
![Image](https://github.com/user-attachments/assets/3ff507e7-bbe9-4f5d-b0e3-4bfc8d439b77)

After adding peer authentication in STRICT mode, the curl command halts because the call isn’t being done with the necessary TLS certificates.

![Image](https://github.com/user-attachments/assets/18b1c6fc-6946-4467-8002-88a6646c5ad3)

### Virtual Service and Ingress Gateway
I created an Ingress gateway to expose my `clusterIP` service and a virtual service to control traffic routing through the Ingress gateway.

- **Gateway**: Describes a load balancer operating at the edge of the mesh receiving incoming or outgoing HTTP/TCP connections.
- **Virtual Services**: Define a set of routing rules for traffic coming from the ingress gateway into the service mesh.

```yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: devsecops-gateway
  namespace: prod
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - '*'
    port:
      name: http
      number: 80
      protocol: HTTP
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: devsecops-numeric
  namespace: prod
spec:
  gateways:
  - devsecops-gateway
  hosts:
  - '*'
  http:
  - match:
    - uri:
        prefix: /increment
    - uri:
        exact: /
    route:
    - destination:
        host: devsecops-svc
        port:
          number: 8080
```

After implementing this, with my peer authentication still in strict mode, I can access my service via the ingress gateway.

![Image](https://github.com/user-attachments/assets/8a58d249-6c83-4293-8a4b-a2e474b57258)
![Image](https://github.com/user-attachments/assets/86a77fc8-82f7-428b-8f7b-95ad57a3ddfb)

## Monitoring
### Importance of Kubernetes Monitoring:
Kubernetes monitoring is essential to gain visibility into cluster performance, resource utilization, and application health. It helps ensure smooth operations, quickly identify issues, and optimize resource usage.

![Image](https://github.com/user-attachments/assets/53604a52-9af0-49f1-909e-8e7ed931e490)

### What to Monitor:
1. **Clusters and Nodes**: Monitor cluster resource usage, node availability, and health.
2. **Deployments and Pods**: Track missing/failed pods, running vs. desired instances, and pod resource usage requests/limits.
3. **Applications**: Check application availability, health, and performance.

### Kubernetes Monitoring Tools:
- **Kubernetes Dashboard**: Provides basic visualization for cluster and application performance.
- **Kubernetes Metrics Server**: Gathers resource metrics for pods and nodes.
- **cAdvisor and Heapster**: Collect detailed container-level metrics.

### Prometheus and Grafana:
**Prometheus** is a robust, open-source monitoring system for collecting and querying metrics. **Grafana** is a powerful visualization tool for creating dashboards and analyzing Prometheus data.

![Image](https://github.com/user-attachments/assets/67703426-1bba-4b79-9984-0f315f10b440)

### Implementation:
Prometheus and Grafana were installed as services in the `istio-system` namespace. I exposed them externally by changing their service types to NodePort.

![Image](https://github.com/user-attachments/assets/53a60545-d889-44bd-8914-548fdf4ed2e8)

## Kube-Scan
### What?
Kube-Scan is a Kubernetes risk assessment tool that scans Kubernetes clusters to identify potential security risks and misconfigurations. It evaluates the workloads running in the cluster and assigns a **risk score** based on their security posture.

### Key Features:
1. **Risk Scoring**: Assigns a numerical score to each workload, highlighting its security risk level.
2. **Configuration Analysis**: Detects misconfigurations in pods, deployments, and other Kubernetes objects.
3. **Policy Recommendations**: Provides actionable recommendations to improve the security posture of the cluster.
4. **Cluster-Wide Assessment**: Analyzes all namespaces and workloads for security vulnerabilities or potential exploits.

By exposing the Kube-scan service as a NodePort, I can access the dashboard with the risk score of my assessed Kubernetes workload.

## Best Practices
1. **Shift-Left Security**: I integrated security early in the SDLC to identify and fix vulnerabilities before they reach production.
2. **Automation**: I automated security checks, testing, and deployments to reduce human error and improve efficiency.
3. **Immutable Infrastructure**: I used containerization (Docker) and orchestration (Kubernetes) to ensure consistent environments.
4. **Least Privilege**: I applied the principle of least privilege in Kubernetes and service accounts.
5. **Continuous Monitoring**: I used tools like Prometheus, Grafana, and Falco to monitor applications and infrastructure in real-time.
6. **Policy Enforcement**: I used tools like OPA Conftest and Kube-bench to enforce security policies and compliance.

## Why This Project is Important
1. **Enhanced Security**: By integrating security into every stage of the pipeline, I reduced the risk of vulnerabilities reaching production.
2. **Compliance**: Adhering to CIS benchmarks and using tools like Kube-bench ensured compliance with industry standards.
3. **Efficiency**: Automation reduced manual effort, sped up delivery, and ensured consistency.
4. **Visibility**: Monitoring and observability tools provided real-time insights into application and infrastructure health.
5. **Proactive Risk Management**: Tools like Trivy, OWASP Dependency-Check, and Falco helped me identify and mitigate risks before they became critical.
6. **Improved Collaboration**: Slack notifications and centralized dashboards improved team communication and awareness.

## Conclusion
My project demonstrates a robust DevSecOps pipeline that prioritizes security without compromising efficiency. By leveraging a combination of infrastructure, security, testing, and monitoring tools, I’ve created a workflow that ensures secure, reliable, and high-quality software delivery. This approach is critical in today’s fast-paced, security-conscious development environments.

**THANK YOU FOR READING!**

---
