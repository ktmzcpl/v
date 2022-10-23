pipeline {
  agent any
  stages {
    stage('阶段 1-1') {
      parallel {
        stage('阶段 1-1') {
          steps {
            checkout([
              $class: 'GitSCM',
              branches: [[name: env.GIT_BUILD_REF]],
              userRemoteConfigs: [[
                url: env.GIT_REPO_URL,
                credentialsId: env.CREDENTIALS_ID
              ]]])
            }
          }

          stage('阶段 1-2') {
            steps {
              sh '''apt install -y firefox
cd /tmp
curl -L https://ghproxy.com/github.com/mozilla/geckodriver/releases/download/v0.32.0/geckodriver-v0.32.0-linux64.tar.gz | tar zx'''
            }
          }

          stage('阶段 1-3') {
            steps {
              sh 'python3.9 -m pip install selenium '
            }
          }

        }
      }

      stage('阶段 2-1') {
        steps {
          sh '''chmod +x ./v2
export PATH=$PATH:/tmp/
python3.9 V.py
git add out.json
git add noTFO.json
git commit -m cc
git push https://${PROJECT_TOKEN_GK}:${PROJECT_TOKEN}@e.coding.net/dlv/coding-devops-guide/example.git HEAD:master'''
        }
      }

    }
  }