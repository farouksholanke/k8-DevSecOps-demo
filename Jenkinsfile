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
            post {
              always {
                junit 'target/surefire-reports/*.xml'
                jacoco execPattern: 'target/jacoco.exec'
              }
            }
      }

      stage('Mutation Tests - PIT') {
        steps {
          sh "mvn org.pitest:pitest-maven:mutationCoverage"
        }
      
        post {
          always {
            pitmutation mutationStatsFile: '**/target/pit-reports/**/mutations.xml'
          }
        }
      }

      stage('SonarQube - SAST') {
        steps {
           withSonarQubeEnv('SonarQube') {
              sh "mvn sonar:sonar \
                                    -Dsonar.projectKey=numeric-application \
                                    -Dsonar.host.url=http://devsecops-demo.eastus.cloudapp.azure.com:9000
                                    -Dsonar.login=sqp_d478f69c72233f121aedc6cdadb3d3975bd5f046"


           }

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
}