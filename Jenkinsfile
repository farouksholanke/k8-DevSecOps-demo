pipeline {
  agent any

  stages {
      stage('Build Artifact') {
            steps {
              sh "mvn clean package -DskipTests=true"
              archive 'target/*.jar' //so that they can be downloaded later
            }
        }   

      stage('Unit Tets - JUnit and Jacoco') {
            steps {
              sh "mvn test"
            }
      }

      stage('Mutation Tests - PIT') {
        steps {
          sh "mvn org.pitest:pitest-maven:mutationCoverage"
        }
      }

      stage('SonarQube -SAST') {
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
          timeout(time: 2, unit: 'MINUTES') {
            script {
              waitForQualityGate abortPipeline: true
            }

          }
        }
      }

      stage('Vulnerability Scan - Docker') {
        steps {
          sh "mvn dependency-check:check"
        }
      }

      stage('Docker Build and Push'){
        steps {
         withDockerRegistry([credentialsId: "docker-hub", url: ""]) {
           sh 'printenv'
           sh 'sudo docker build -t farouksholanke/numeric-app:""$GIT_COMMIT"" .'
           sh 'docker push farouksholanke/numeric-app:""$GIT_COMMIT""'
        }
       }
      }

      stage('Kubernetes Deployment - DEV') {
        steps {
          withKubeConfig([credentialsId: 'kubeconfig']) {
              sh "sed -i 's#replace#farouksholanke/numeric-app:${GIT_COMMIT}#g' k8s_deployment_service.yaml"
               sh "kubectl apply -f k8s_deployment_service.yaml"
          }
        }
    }
  }

  post {
    always {
      junit 'target/surefire-reports/*.xml'
      jacoco execPattern: 'target/jacoco.exec'
      pitmutation mutationStatsFile: '**/target/pit-reports/**/mutations.xml'
      dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'
    }
  }
}