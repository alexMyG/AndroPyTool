# Alpine Linux with python 2.7 and Oracle Java 8
FROM ubuntu:artful

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
 && add-apt-repository ppa:webupd8team/java -y \
 && apt-get update \
 && echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections \
 && apt-get install -y oracle-java8-installer \
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
	ANDROID_EMULATOR_FORCE_32BIT=true

# Preparing droidbox
RUN pwd \
 && cd /root \
 && git clone https://github.com/alexMyG/DroidBox-AndroPyTool \
 # && wget -P /root/DroidBox-AndroPyTool/images https://github.com/alexMyG/DroidBox-AndroPyTool/raw/master/images/system.img \
 # && wget -P /root/DroidBox-AndroPyTool/images https://github.com/alexMyG/DroidBox-AndroPyTool/raw/master/images/ramdisk.img \
 && echo "no" | DroidBox-AndroPyTool/createDroidBoxDevice.sh \
 && chmod 744 DroidBox-AndroPyTool/*.sh \
 && pip install -U setuptools wheel \
 && pip install -r DroidBox-AndroPyTool/requirements.txt

VOLUME /apks

EXPOSE 5554 5555

CMD /root/DroidBox-AndroPyTool/run.sh
# CMD bash -c "python /root/DroidBox-AndroPyTool/fork_droidbox.py /apks 300 False"
