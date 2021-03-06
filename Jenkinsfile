// https://www.jenkins.io/doc/book/pipeline/docker/
pipeline {
    agent {
        docker {
            image 'piersfinlayson/build-amd64:0.3.3'
        }
    }
    stages {
        stage('Clone') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'github.packom', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                    sh '''
                        cd /home/build/builds && \
                        git clone https://packom:$PASSWORD@github.com/packom/httpd-util && \
                        cd httpd-util && \
                        echo `awk '/^version / {print $3;}' Cargo.toml | sed 's/"//g'` > /tmp/version && \
                        echo "Current version is:" && \
                        cat /tmp/version
                    '''
                }
            }
        }
        stage('Build') {
            steps {
                sh '''
                    cd /home/build/builds/httpd-util && \
                    cargo build
                '''
            }
        }
        stage('Test') {
            steps {
                sh '''
                    cd /home/build/builds/httpd-util && \
                    cargo test
                    cargo test -- --ignored
                '''
            }
        }
        stage('Publish') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'crates.packom', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                    sh '''
                        cd /home/build/builds/httpd-util && \
                        CURV=$(cat /tmp/version) && \
                        echo `cargo search httpd-util | awk '/^httpd-util / {print $3;}' | sed 's/"//g'` > /tmp/old_version && \
                        echo "Old version is:" && \
                        cat /tmp/old_version && \
                        OLDV=$(cat /tmp/old_version) && \
if [ $CURV != $OLDV ]
then
    cargo publish --token $PASSWORD 
else
    echo "No changes to publish"
fi
                    '''
                }
            }
        }
    }
}
