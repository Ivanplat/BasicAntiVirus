#pragma once
#include "pch.h"
/// \file
///\brief


class Application
{
public:
	/// <summary>
	/// Default constructor that inialize a HINSTANCE of the application
	/// </summary>
	/// <param name="hInstance"></param>
	/// <returns>void</returns>
	explicit Application(HINSTANCE hInstance) noexcept : hInstance(hInstance) {};
	virtual ~Application() noexcept = default;
public:
	/// <summary>
	/// Startup methode.
	/// Calling branch:
	/// \code
	/// CreateWindowClass();
	/// CreateApplicationWindow();
	/// MainLoop();
	/// \endcode
	/// </summary>
	/// <returns>void</returns>
	virtual void Startup() noexcept;
private:

	/// <summary>
	/// CreateWindowClass methode. Create a main window class and register it. 
	/// </summary>
	/// <returns>void</returns>
	virtual void CreateWindowClass();
	/// <summary>
	/// CreateApplicationWindow methode. Create the main window and show it on a screen.
	/// </summary>
	/// <returns>void</returns>
	virtual void CreateApplicationWindow();
	/// <summary>
	/// MainLoop methode. While working. Catching the Windows messages and reply it for handler WinProc() methode.
	/// </summary>
	/// <returns>void</returns>
	virtual void MainLoop();
private:
	/// <summary>
	/// Handler methode of the Windows messages.
	/// </summary>
	/// <returns>LRESULT</returns>
	static LRESULT WINAPI WinProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam);
private:
	/// HINSTANCE of the application
	HINSTANCE hInstance;
	/// WNDCLASSEX of the application
	WNDCLASSEX WndClass;
	/// hWnd of the main window of the application
	HWND hWnd;
	/// Main window class name
	WCHAR WindowClass[MAX_STRING_LENGH];
	/// Main window name
	WCHAR WindowName[MAX_STRING_LENGH];
};
