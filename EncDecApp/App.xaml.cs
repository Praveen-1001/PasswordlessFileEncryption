using System;
using System.Windows;

namespace EncDecApp
{
    public partial class App : Application
    {
        // App-wide exception handling
        public App()
        {
            this.DispatcherUnhandledException += App_DispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        }

        private void App_DispatcherUnhandledException(object sender,
            System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show($"An unexpected error occurred: {e.Exception.Message}",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }

        private void CurrentDomain_UnhandledException(object sender,
            UnhandledExceptionEventArgs e)
        {
            var exception = e.ExceptionObject as Exception;
            MessageBox.Show($"A fatal error occurred: {exception?.Message ?? "Unknown error"}",
                "Fatal Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}