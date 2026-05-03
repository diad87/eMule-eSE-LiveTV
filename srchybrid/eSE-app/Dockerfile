FROM eclipse-temurin:17-jdk

# Android SDK
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PATH="${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools"

RUN apt-get update && apt-get install -y wget unzip && \
    mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    cd ${ANDROID_SDK_ROOT}/cmdline-tools && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O tools.zip && \
    unzip -q tools.zip && mv cmdline-tools latest && rm tools.zip && \
    yes | sdkmanager --licenses > /dev/null 2>&1 && \
    sdkmanager "platforms;android-34" "build-tools;34.0.0" "platform-tools" > /dev/null 2>&1

# Install Gradle
RUN wget -q https://services.gradle.org/distributions/gradle-8.4-bin.zip -O /tmp/gradle.zip && \
    unzip -q /tmp/gradle.zip -d /opt && rm /tmp/gradle.zip
ENV PATH="${PATH}:/opt/gradle-8.4/bin"

WORKDIR /app
COPY . .

# Generate wrapper and build
RUN gradle wrapper --gradle-version=8.4 && \
    chmod +x gradlew && \
    ./gradlew assembleDebug --no-daemon

# Copy APK to output on run
CMD ["sh", "-c", "cp app/build/outputs/apk/debug/*.apk /output/ && echo 'APK copied to /output/'"]
