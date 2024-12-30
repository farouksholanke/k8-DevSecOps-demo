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
               sh "kubectl -n prod apply -f k8s_PROD-deployment_service.yaml"
          }
        }
    }
  }
}