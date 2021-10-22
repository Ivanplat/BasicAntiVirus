#include "pch.h"
#include "Core/SHA-Checker/public/SHACheker.h"
#include "WinAPI/public/App.h"

/// \file

/// \brief  Main function
/// \param  hInstance instance of the entry point of the application
/// \param  hPrevInstance does not use
/// \param  lpCmdLine arguments of the cmd
/// \param  nShowCmd int that showing how application should shows
/// \return an integer 0 upon exit success


int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{


	//std::ifstream input("C:\\1.png", std::ios::binary);
	//std::ofstream output("C:\\321.jpg", std::ios::binary);

	//std::string buffer(std::istreambuf_iterator<char>(input), {});

	//SHAChecker SH;
	//
	//SH.GetHash(buffer);

	Application* App = new Application(hInstance);
	App->Startup();
	delete App;
	App = nullptr;

	return 0;
}


