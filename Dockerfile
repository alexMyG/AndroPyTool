# Alpine Linux with python 2.7 and Oracle Java 8
FROM ubuntu:bionic
ENV DEBIAN_FRONTEND=noninteractive 

# Installing Oracle JDK 8
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
 		software-properties-common \
 		wget \
 		git \
		lib32gcc1 \
		lib32ncurses5 \
		lib32stdc++6 \
		lib32z1 \
		libc6-i386 \
		libgl1-mesa-dev \
		python-pip \
		python-dev \
		gcc \
 		python-tk \
 		curl \
 && echo "y" | apt-get install openjdk-8-jdk \
 && echo "y" | apt-get install openjdk-8-jre \
 && apt-get install -y python-setuptools unzip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Installing Android SDK and Android 16
RUN cd / \
 && wget -qO- http://dl.google.com/android/android-sdk_r24.2-linux.tgz | tar xz -C /root/ --no-same-permissions \
 # && wget http://dl.google.com/android/android-sdk_r24.2-linux.tgz \
 # && tar xfz android-sdk_r24.2-linux.tgz \
 # && ln -s /android-sdk-linux/tools/android /usr/bin/android
 && chmod -R a+rX /root/android-sdk-linux \
 && echo y | /root/android-sdk-linux/tools/android update sdk --filter tools --no-ui --force -a \
 && echo y | /root/android-sdk-linux/tools/android update sdk --filter platform-tools --no-ui --force -a \
 && echo y | /root/android-sdk-linux/tools/android update sdk --filter android-16 --no-ui --force -a \
 && echo y | /root/android-sdk-linux/tools/android update sdk --filter sys-img-armeabi-v7a-android-16 --no-ui -a

ENV ANDROID_HOME="/root/android-sdk-linux" \
	PATH=$PATH:/root/android-sdk-linux/platform-tools:/root/android-sdk-linux/tools \
	ANDROID_EMULATOR_FORCE_32BIT=true \
	TERM=linux \
	TERMINFO=/etc/terminfo

RUN pwd \
 && cd /root/ \
 && git clone --recursive https://github.com/alexMyG/AndroPyTool.git \
 && wget https://github.com/alexMyG/AndroPyTool/releases/download/droidbox_images_patched/images_droidbox.zip \
 && unzip -o images_droidbox.zip -d AndroPyTool/DroidBox_AndroPyTool/images \
 && pip install wheel \
 && pip install -r AndroPyTool/requirements.txt \
 && touch AndroPyTool/avclass/__init__.py \
 && chmod 744 /root/AndroPyTool/run_androPyTool.sh


# Preparing droidbox
RUN pwd \
 && cd /root/ \
 && chmod 744 AndroPyTool/DroidBox_AndroPyTool/*.sh \
 && echo "no" | ./AndroPyTool/DroidBox_AndroPyTool/createDroidBoxDevice.sh

RUN adb devices; exit 0

VOLUME /apks

EXPOSE 5554 5555

WORKDIR /root/AndroPyTool/

ENTRYPOINT ["python", "-u", "/root/AndroPyTool/androPyTool.py"]
#CMD cd






