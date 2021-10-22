#include "pch.h"
#include "WinAPI/public/App.h"

/// \file


void Application::Startup() noexcept
{
	CreateWindowClass();
	CreateApplicationWindow();
	MainLoop();
}



void Application::CreateWindowClass()
{

	LoadString(hInstance, IDS_WindowClassName, WindowClass, MAX_STRING_LENGH);
	LoadString(hInstance, IDS_WindowName, WindowName, MAX_STRING_LENGH);

	WndClass.cbSize = sizeof(WNDCLASSEX);
	WndClass.cbWndExtra = 0;
	WndClass.cbClsExtra = 0;
	WndClass.hInstance = hInstance;
	WndClass.lpszClassName = WindowClass;
	WndClass.lpfnWndProc = Application::WinProc;
	WndClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	WndClass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	WndClass.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	WndClass.lpszMenuName = nullptr;
	WndClass.hbrBackground = (HBRUSH)GetStockObject(NULL_BRUSH);
	WndClass.style = CS_OWNDC;

	RegisterClassEx(&WndClass);
}


void Application::CreateApplicationWindow()
{ 
	hWnd = CreateWindow(WindowClass, WindowName, WS_OVERLAPPEDWINDOW, 300, 300, 600, 800, nullptr, nullptr, hInstance, nullptr);
	ShowWindow(hWnd, SW_SHOW);
}

/// \endcode


void Application::MainLoop()
{
	MSG msg{};
	while (GetMessage(&msg, hWnd, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}


LRESULT WINAPI Application::WinProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam)
{
	switch (uMessage)
	{
	case WM_QUIT:
	{
		return 0;
	}break;
	default:
	{
		return DefWindowProc(hWnd, uMessage, wParam, lParam);
	}break;
	}
}