@echo off
@set path=%path%;c:\python27\

if exist Release (
    @del /Q /S Release > nul
)

if exist "key.skr" @del key.skr > nul
if exist "key.pkr" @del key.pkr > nul
    
@echo [*] Engine file copy to release folder...
@xcopy Engine\* Release\ /e > nul

@python.exe Tool\mkkey.py 
if not exist "key.pkr" goto KEY_NOT_FOUND
if not exist "key.skr" goto KEY_NOT_FOUND

@copy key.* Release\plugins > nul
@copy Tool\kmake.py Release\plugins > nul
@cd Release\plugins

@echo [*] Build Engine files...
@python.exe kmake.py kicom.lst

for %%f in (*.py) do (
    if %%f neq kmake.py (
        @python.exe kmake.py %%f
    )    
)

@ren key.pkr kicomav.pkr > nul
@del /Q *.py > nul
@del kicom.lst > nul
@del key.skr > nul 

@cd ..
goto END

:KEY_NOT_FOUND
@echo     Key files not Found!!!
goto END

:END
