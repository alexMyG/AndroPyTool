#Testing
# Alejandro Cortinas
from androguard.core.bytecodes import apk
import subprocess
import os,sys
import argparse
import logging
import time
import os
import shutil
import struct
import subprocess, signal
print "------WARNING------"
print "This scripts kills any java process of the user. Execute with precaution!"
print "-------------------"

USER_NAME = "alejan" # To kill java processes


# Path to flowdroid
flowdroid_path = os.getcwd() + "/"
flowdroid_executables_path = flowdroid_path + "../flowDroidExecutables/"

# Android SDK root path
android_sdk_home = flowdroid_path + '../../android-platforms/platforms'

# flowdroid classhpath
classpath=flowdroid_executables_path + "soot-trunk.jar:" + flowdroid_executables_path + "soot-infoflow.jar:" + flowdroid_executables_path + "soot-infoflow-android.jar:" + flowdroid_executables_path + "slf4j-api-1.7.5.jar:" + flowdroid_executables_path + "slf4j-simple-1.7.5.jar:" + flowdroid_executables_path + "axml-2.0.jar"
order = ''
mode = ''
limit = 0
slimit = 0
timeout = 0
global make_
global mlogger
timeout_reached = False

def main(args):
	global make_
	global order
	global mode
	global limit
	global slimit
	global timeout
	global timeout_reached
	analyzed_samples = 0
	total_samples = 0
	crashed_samples = 0

	#create log
	mlogger = create_logger('dlog.txt')
	parser = argparse.ArgumentParser(description='Launch flowdroid tests over the malgenome repository.')
	parser.add_argument('-m','--mode', help='Select the mode for processing the whole dataset.\nPosible Values are:\nsequential: analyzes all the families in alphabetical order.\nordered: analyzes the dataset in an ordered fashion according to app sizes.', required=True)
	parser.add_argument('-o','--order', help='When mode is ordered, select if the files must be analyzed from bigger to smaller [descending] or opposite [ascending]', required=False)
	parser.add_argument('-l','--limit', help='Specify the maximum number of analyzed samples. If not specified all samples will be analyzed.', required=False)
	parser.add_argument('-s','--slimit', help='Specify the size (in MB) threshold for analyzing the app. If not specified all samples will be analyzed.', required=False)
	parser.add_argument('-t','--timeout', help='Specify the timeout (in minutes) for analyzing the app. If not specified not timeout will be considered.', required=False)
	parser.add_argument('-r','--repo', help='Specify the path where apks are located.', required=True)
	parser.add_argument('-f','--folder', help='Specify the folder where analysis must be saved.', required=True)

	args = parser.parse_args()

	#retrieve parameters
	try:
		if args.mode:
			mode = str(args.mode)
			print 'mode set to: '+mode
		if mode == 'ordered':
			order = str(args.order)
			print 'order set to: '+order
		if args.limit:
			limit = int(args.limit)
			print 'limit set to: '+str(limit)
		else:
			limit = sys.maxint
		if args.slimit:
			slimit = float(args.slimit)
			print 'size limit set to: '+str(slimit) +' MB'
		else:
			slimit = float(0.0)
		if args.timeout:
			timeout = int(args.timeout)
			print 'timeout set to '+str(timeout)+' minutes'

		if args.repo:
			repo_path = args.repo

		if args.folder:
			flowdroid_outputs = args.folder

	except ValueError,TypeError:
		print 'Error parsing the parameters. Check parameter type and try again.'
		sys.exit(-1)

	print '##########################################################################################'
	print '##########################################################################################'
	print '##########################################################################################'
	print '##########################################################################################'
	print '					 			BEGINNING EXECUTION 									 '
	print '##########################################################################################'
	mlogger.info('beginning execution')
	millis_a = int(round(time.time() * 1000))

	#create output folder
	if not os.path.isdir(flowdroid_outputs):
		os.makedirs(flowdroid_outputs)




	if mode == 'ordered':

		if (not order=='ascending') and (not order=='descending'):
			print 'Wrong option provided for order parameter. Available options are: descending or ascending'
			sys.exit(-1)

		apk_list = []
		if order == 'descending':
			apk_list = get_ordered_apk_list(repo_path,reverse=True)
		else:
			apk_list = get_ordered_apk_list(repo_path,reverse=False)
		print len(apk_list)
		mlogger.info('Running analysis with ordered ('+order+') dataset')
		#apk_list=apk_list[21:]
		#print len(apk_list)
		print "NUM APKS: " + str(len(apk_list))

		for app in [f for f in apk_list if f[0].endswith(".apk")]:

			print "Searching previous Java processes..."
			p = subprocess.Popen(['ps', '-aux'], stdout=subprocess.PIPE)
			out, err = p.communicate()
			for line in out.splitlines():
				if 'java' in line and USER_NAME in line:
					pid = int(line.split()[1])
					try:
						os.kill(pid, signal.SIGKILL)
					except OSError:
						break
					print "PROCESS " + str(pid) + " KILLED!"


			print "\n\n\n"
			print app
			if total_samples<limit:
				if (slimit!=0.0 and get_file_size(app[0])<=slimit) or slimit==0.0:
					total_samples = total_samples+1
					#create apk instance
					try:
						my_apk = apk.APK(app[0])
					except:
						continue
					packagename = my_apk.get_package()
					#apk_dir_name = # app[0].split('/')[5].replace('.apk','')+'_'+packagename
					apk_dir_name = app[0].split('/')[-1].replace('.apk', '')
					apk_folder = flowdroid_outputs+'/'+app[0].split('/')[4]+'/'+apk_dir_name

					#create output folder for this sample
					if not os.path.isdir(apk_folder):
						os.makedirs(apk_folder)
						mlogger.info('Creating folder for sample '+app[0]+': '+apk_folder)
					else:
						mlogger.info("APK already analysed. Continue..."+app[0]+': '+apk_folder)
						continue

					#create_makefile(apk_folder,app[0],app[0].split('/')[6])

					os.chdir(apk_folder)
					shutil.copyfile(flowdroid_path + 'AndroidCallbacks.txt', apk_folder+'/AndroidCallbacks.txt')
					shutil.copyfile(flowdroid_path + 'EasyTaintWrapperSource.txt', apk_folder+'/EasyTaintWrapperSource.txt')
					shutil.copyfile(flowdroid_path + 'SourcesAndSinks.txt', apk_folder+'/SourcesAndSinks.txt')

					print 'Launching flowdroid on '+app[0]
					mlogger.info('Launching flowdroid on '+apk_folder)

					millis_sa = int(round(time.time() * 1000))
					new_env = os.environ.copy()
					new_env['CLASSPATH'] = classpath
					new_env['PLATFORM'] = android_sdk_home
					print app[0]
					#make_ = subprocess.Popen("/usr/bin/make specdump-apk", stderr=subprocess.STDOUT, shell=True,env=new_env)

					command='cpulimit -l 1800 java -Xmx100g -cp $CLASSPATH soot.jimple.infoflow.android.TestApps.Test '+app[0]+' $PLATFORM'


					#Before execution for tensorflow
					#command='cpulimit -l 1000 java -Xmx150g -cp $CLASSPATH soot.jimple.infoflow.android.TestApps.Test '+app[0]+' $PLATFORM --nostatic --aplength 1 --aliasflowins --nocallbacks --layoutmode none --noarraysize'
					#command='java -Xmx30g -cp $CLASSPATH soot.jimple.infoflow.android.TestApps.Test '+app[0]+' $PLATFORM  --aliasflowins --layoutmode none --noarraysize'

					print command
					make_ = subprocess.Popen(command, stderr=subprocess.STDOUT,stdout=open('flowdroid_'+app[0].split('/')[5].replace('.apk','')+'.txt', 'wb'), shell=True,env=new_env)
					#make_ = subprocess.Popen(command, stderr=subprocess.STDOUT, shell=True,env=new_env)


					if timeout>0:
						#set the signal for timeout
						signal.signal(signal.SIGALRM, interruptHandler)
						#convert to seconds
						signal.alarm(timeout*60)
					if make_.wait() !=0:
						millis_sb = int(round(time.time() * 1000))

						if timeout_reached:
							mlogger.error('Killing analysis os current app. Max. time ('+str(timeout*60)+' sec.) reached .')
							timeout_reached = False
						else:
							print 'Error executing flowdroid\'s make at application '+ str(total_samples)+' . Quitting...'

						crashed_samples=crashed_samples+1
						mlogger.error('Error executing flowdroid\'s make at application '+ str(total_samples)+'('+app[0]+')'+' after '+str((millis_sb-millis_sa)/1000.0) +' seconds ('+str(((millis_sb-millis_sa)/1000.0)/3600.0)+' hours)')

					else:
						millis_sb = int(round(time.time() * 1000))
						print 'flowdroid succesfully executed in '+app[0]+' in '+str((millis_sb-millis_sa)/1000.0) +' seconds ('+str(((millis_sb-millis_sa)/1000.0)/3600.0)+' hours)'
						analyzed_samples=analyzed_samples+1
						mlogger.info('flowdroid Successfully executed at application %d '+'('+app[0]+')'+' after '+str((millis_sb-millis_sa)/1000.0) +' seconds ('+str(((millis_sb-millis_sa)/1000.0)/3600.0)+' hours)',total_samples)

				else:
					mlogger.warning('apk '+app[0]+' is too big for analysis ('+str(get_file_size(app[0]))+' MB)')
			else:
				mlogger.warning('Reached maximum number (%d) of samples',limit)
				break

	else:
		print 'Error bad argument: ' +mode
		sys.exit(-1)


	millis_b = int(round(time.time() * 1000))
	print '____________________________________________________'
	print '					   STATS						'
	print '____________________________________________________'
	print 'total time '+str((millis_b-millis_a)/1000.0) +' seconds ('+str(((millis_b-millis_a)/1000.0)/3600.0)+' hours)'
	print 'Total analyzed samples '+str(total_samples)
	print 'Successfully analyzed samples '+str((analyzed_samples/float(total_samples))*100.0)
	print 'Crashed Samples :'+str((crashed_samples/float(total_samples))*100.0)






def list_directory(path,level='dirs'):

	 for path, dirs, files in os.walk(path):
	 	if level == 'dirs':
	 		return dirs
	 	elif level == 'files':
	 		for file in files:
	 			if file.endswith(".json"):
	 				files.remove(file)
	 		return files

def get_ordered_apk_list(path,reverse=False):
	filepaths = []

	print "PATH: " + str(path)
	print "\n\n\nCONTENIDO: " + path
	for d in list_directory(path):

		for f in list_directory(path+'/'+d,level='files'):
			full_path = path+'/'+d+'/'+f
			filepaths.append(full_path)

	for i in xrange(len(filepaths)):
		filepaths[i] = (filepaths[i], os.path.getsize(filepaths[i]))

	filepaths.sort(key=lambda filename: filename[1], reverse=reverse)
	return filepaths

def create_logger(log_filename):

	logger = logging.getLogger(__name__)
	logger.setLevel(logging.INFO)

	# create a file handler

	handler = logging.FileHandler(log_filename)
	handler.setLevel(logging.INFO)

	# create a logging format

	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)

	# add the handlers to the logger

	logger.addHandler(handler)

	return logger

def get_file_size(path):
	size = (os.path.getsize(path)/float(1000000))
	#TODO: check if the path is a file
	return size

def create_makefile(path,apkpath,apkname):
	makefile = open(path+'/Makefile','w')
	makefile.write('NAME := '+apkname.replace('.apk','')+'\n')
	makefile.write('APK  := '+apkpath+'\n')
	makefile.write('ifndef flowdroid_SRC_HOME\n')
	makefile.write('$(error flowdroid_SRC_HOME is undefined)\n')
	makefile.write('endif\n')
	makefile.write('include $(flowdroid_SRC_HOME)/android-apps/Makefile.common\n')
	makefile.close()

def interruptHandler(signum, frame):
	print 'signal received'
	global timeout_reached
	timeout_reached = True
	kill_droid_safe_process()

def kill_droid_safe_process():
	global make_
	make_.kill()

if __name__ == '__main__':
	main(sys.argv)
