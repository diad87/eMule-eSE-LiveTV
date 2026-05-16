This is an example of how to use id3com.dll with Delphi. This has only 
been tested this using Delphi 4 but I believe it will work with Delphi 
3 and 5 just fine. I basically ported the visual basic example to
delphi. If you get stuck or have any qeustions please feel free to 
contact me at mike@netlinear.com.

I included the executable, source code and the type library file needed
for developing applications using the com object (id3com.dll).

You will need a current, compiled version of the id3com.dll. You can either
compile it yourself using the Visual C++ workspace provided in the id3com
directory or you can download a pre-compiled version from the id3lib the 
id3lib download page, found at the following URL:

http://sourceforge.net/project/filelist.php?group_id=979

To use the dll you must first register it using regsvr32.exe, like so:

"c:\windows\system\regsvr32.dll c:\location of id3com.dll\id3com.dll"

You should see a message, "DllRegisterServer in id3com succeeded",
indicating the dll was registered.

To use the dll with Delphi you must either use the included ID3COM_TLB.pas 
type library or import the type library in the following manner:

1. Register the dll as instructed above. You do not have to restart Windows.

2. Start Delphi and create or open a project.

3. Click on "Project | Import Type Library...". A list box will be displayed, 
scroll down until you find "ID3COM 1.0 Type Library (Version 1.0)".

4. Click "Add".

5. A file called ID3COM_TLB.pas is created in your \delphi4\imports directory
and A refernce to the type library gets added to your project source file, 
you should also add it to the uses clause in any unit that will refrence the 
object. Look as my example.

You do not have to do this everytime you create a project, it only needs to be 
done if the com object has changed. Once your register the com object and 
create a type library file once, you can use it in any application. Just 
reference the lib file (ID3COM_TLB.pas).