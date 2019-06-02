# DOR
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//	Overview to DOR:
//	DOR is actually called DOR-JoSuSy which means Development of Remote System for Job Submission on a HPC Cluster
//	This project was tested on a cluster consisting of 1head and 3slaves configured to SLURM scheduler
//	This project has features like
//		-> Job Submission
//		-> Job Monitoring
//		-> Cluster Monitoring 
//		-> Node Monitoring(separately)
//		-> Viewing list of users executable path and his home area content on the cluster
//		-> Upload executable to cluster while submiting jobs
//		-> Basic feature like change password, which would change user's cluster and portal password
//		-> Information regarding cluster
//		-> Admin can add/ remove users to cluster & view system log
//
//	It was developed using Django.
//	Attempt of making it reunderstandable is made, if anything bothers you please do leave a comment
//	Good luck! Hope so you like it!
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

===========================================================================================================================
|												   																		|
|						Installation process for tools used in DRS-JoSuSy												|
|																														|
===========================================================================================================================

 Step (1) Visit following link
	https://pypi.org/project/setuptools/#files

****************************************************************************************************************************************
****************************************************************************************************************************************
	
 Step 2) Click and download "setuptools-41.0.0.zip"
		 Approximate size 900kB

****************************************************************************************************************************************
****************************************************************************************************************************************
	
 Step 3) Unzip it. 
			=> May require unzipping tools
			=> Or you can unzip it by just following steps
				- Right Click on 'setuptools-41.0.0.zip'
				- Extract here OR Extract to any desrired location (Make sure its easy to access)
	
****************************************************************************************************************************************
****************************************************************************************************************************************
	
 Step 4) Reach 'setuptools-41.0.0' directory from terminal and execute following command
	
	$ sudo python3 setup.py install

****************************************************************************************************************************************
****************************************************************************************************************************************

 Step 5) May raise a require dependency message, for requiring 'pytz-2019.1'
			=> Visit https://pypi.org/search/?q=pytz-2019.1.tar.gz
			=> Download 'pytz-2019.1.tar.gz'
			=> Reach to the directory in which 'pytz-2019.1.tar.gz' is downloaded via terminal & type following command
			
	$ tar -xvzf pytz-2019.1.tar.gz
	
			=> Reach to 'pytz-2019.1' directory from terminal and execute following command
	
	$ sudo python3 setup.py install 
	
****************************************************************************************************************************************
****************************************************************************************************************************************

 Step 6) Download Django for intalling
			=> Visit https://www.djangoproject.com/download/
			=> Download Django-2.1.7.tar.gz
			=> As Django isn't developed by full time developers it isn't stable so newer versions might be introduced
			=> Reach to the directory in which 'Django-2.1.7.tar.gz' is downloaded via terminal & type following command

		$ tar-xvzf Django-2.1.7.tar.gz

			=> Reach to 'Django-2.1.7' directory from terminal and execute following command
	
		$ sudo python3 setup.py install 

	check Django Version
	
	|*----------------------------------------------------------------------------------------------*|
	|*	NOTE: Version of Django you are looking for, may have changed.	*|
	|*----------------------------------------------------------------------------------------------*|

****************************************************************************************************************************************
****************************************************************************************************************************************
