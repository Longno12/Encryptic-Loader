using Microsoft.Win32;
using SharpMonoInjector;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace WpfApp1
{
    public class ProcessInfo
    {
        public string Name { get; set; }
        public int ProcessId { get; set; }
        public string Title { get; set; }
        public override string ToString() => $"{Name} - {Title} (PID: {ProcessId})";
    }

    public partial class MainWindow : Window
    {
        private readonly List<ProcessInfo> allProcesses = new();
        private readonly Brush successBrush = new SolidColorBrush(Color.FromRgb(0, 200, 0));
        private readonly Brush errorBrush = new SolidColorBrush(Color.FromRgb(200, 0, 0));
        private readonly Brush warningBrush = new SolidColorBrush(Color.FromRgb(200, 100, 0));
        private readonly Brush infoBrush = new SolidColorBrush(Color.FromRgb(0, 150, 200));

        public MainWindow()
        {
            InitializeComponent();
            Loaded += Window_Loaded;
            LoadProcesses();
            CheckAdminStatus();
        }

        private void CheckAdminStatus()
        {
            var isAdmin = IsRunningAsAdministrator();
            AdminStatus.Text = isAdmin ? "Running as Administrator" : "NOT running as Admin";
            AdminStatus.Foreground = isAdmin ? successBrush : errorBrush;

            if (!isAdmin)
            {
                SetStatus("Warning: Run as Administrator for better compatibility", Colors.Orange);
            }
        }

        private bool IsRunningAsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            ((Storyboard)FindResource("FadeIn")).Begin(this);
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "DLL Files (*.dll)|*.dll|All Files (*.*)|*.*",
                Title = "Select .NET Assembly to Inject",
                Multiselect = false
            };

            if (dlg.ShowDialog() == true)
            {
                PathTextBox.Text = dlg.FileName;
                ValidateDLL(dlg.FileName);
            }
        }

        private void ValidateDLL(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    DllStatus.Text = "File not found";
                    DllStatus.Foreground = errorBrush;
                    return;
                }

                var ext = Path.GetExtension(path).ToLower();
                if (ext != ".dll")
                {
                    DllStatus.Text = "Not a DLL file";
                    DllStatus.Foreground = errorBrush;
                    return;
                }

                try
                {
                    var assemblyName = AssemblyName.GetAssemblyName(path);
                    DllStatus.Text = $"Valid .NET Assembly: {assemblyName.Name} v{assemblyName.Version}";
                    DllStatus.Foreground = successBrush;
                    TryFindEntryPoint(path);
                }
                catch (BadImageFormatException)
                {
                    DllStatus.Text = "Not a .NET assembly (BadImageFormat)";
                    DllStatus.Foreground = errorBrush;
                }
                catch (FileLoadException ex)
                {
                    DllStatus.Text = $"Has dependencies: {ex.Message}";
                    DllStatus.Foreground = warningBrush;
                }
                catch (Exception ex)
                {
                    DllStatus.Text = $"Error: {ex.GetType().Name}";
                    DllStatus.Foreground = errorBrush;
                }
            }
            catch (Exception ex)
            {
                DllStatus.Text = $"Validation error: {ex.Message}";
                DllStatus.Foreground = errorBrush;
            }
        }

        private void TryFindEntryPoint(string dllPath)
        {
            try
            {
                var assembly = Assembly.LoadFrom(dllPath);
                var types = assembly.GetTypes();

                var entryPoints = new List<string>();

                foreach (var type in types)
                {
                    var staticMethods = type.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)
                        .Where(m => m.GetParameters().Length == 0 && m.ReturnType == typeof(void));

                    foreach (var method in staticMethods)
                    {
                        entryPoints.Add($"{type.Namespace}.{type.Name}.{method.Name}()");
                    }
                }

                if (entryPoints.Count > 0)
                {
                    Debug.WriteLine($"Found {entryPoints.Count} possible entry points:");
                    foreach (var ep in entryPoints)
                    {
                        Debug.WriteLine($"  - {ep}");
                    }
                    var currentText = DllStatus.Text;
                    DllStatus.Text = $"{currentText} - {entryPoints.Count} entry points found";
                }
                else
                {
                    Debug.WriteLine("No suitable entry points found (need static void method with no parameters)");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Cannot inspect DLL methods: {ex.Message}");
            }
        }

        private void LoadProcesses()
        {
            allProcesses.Clear();
            ProcessComboBox.Items.Clear();

            try
            {
                var processes = Process.GetProcesses().Where(p => !string.IsNullOrEmpty(p.ProcessName)).OrderBy(p => p.ProcessName).ToList();

                foreach (var process in processes)
                {
                    try
                    {
                        var info = new ProcessInfo
                        {
                            Name = process.ProcessName,
                            ProcessId = process.Id,
                            Title = process.MainWindowTitle
                        };

                        if (string.IsNullOrEmpty(info.Title))
                            info.Title = "No Window Title";
                        if (info.Title.Length > 50)
                            info.Title = info.Title.Substring(0, 47) + "...";

                        allProcesses.Add(info);
                    }
                    catch
                    {
                        continue;
                    }
                }

                ProcessComboBox.ItemsSource = allProcesses;
                ProcessCount.Text = $"Found {allProcesses.Count} processes";
            }
            catch (Exception ex)
            {
                ProcessCount.Text = $"Error loading processes: {ex.Message}";
            }
        }

        private void RefreshProcesses_Click(object sender, RoutedEventArgs e)
        {
            LoadProcesses();
            SetStatus("Process list refreshed", Colors.LightBlue);
        }

        private void ProcessSearch_TextChanged(object sender, TextChangedEventArgs e)
        {
            var search = ProcessSearchBox.Text.ToLower();

            if (string.IsNullOrWhiteSpace(search))
            {
                ProcessComboBox.ItemsSource = allProcesses;
            }
            else
            {
                var filtered = allProcesses.Where(p => p.Name.ToLower().Contains(search) || p.ProcessId.ToString().Contains(search) || p.Title.ToLower().Contains(search)).ToList();

                ProcessComboBox.ItemsSource = filtered;
            }

            ProcessCount.Text = $"Showing {ProcessComboBox.Items.Count} processes";
        }

        private async void Inject_Click(object sender, RoutedEventArgs e)
        {
            SetStatus("Preparing injection...", Colors.Orange);

            if (ProcessComboBox.SelectedItem == null)
            {
                SetStatus("Please select a target process", Colors.Red);
                ShowMessage("Error", "No process selected. Please choose a target process from the list.");
                return;
            }

            var selected = (ProcessInfo)ProcessComboBox.SelectedItem;
            var dllPath = PathTextBox.Text;

            if (string.IsNullOrWhiteSpace(dllPath))
            {
                SetStatus("Please select a DLL file", Colors.Red);
                ShowMessage("Error", "No DLL file selected. Please click Browse to select a .NET assembly.");
                return;
            }

            if (!File.Exists(dllPath))
            {
                SetStatus("DLL file not found", Colors.Red);
                ShowMessage("Error", $"The DLL file was not found:\n{dllPath}");
                return;
            }

            if (!IsManagedAssembly(dllPath))
            {
                SetStatus("Selected file is not a .NET assembly", Colors.Red);
                ShowMessage("Error", "The selected file is not a valid .NET assembly.\nSharpMonoInjector can only inject .NET DLLs.");
                return;
            }

            Process targetProcess = null;
            try
            {
                targetProcess = Process.GetProcessById(selected.ProcessId);

                if (targetProcess.HasExited)
                {
                    SetStatus("Target process has exited", Colors.Red);
                    ShowMessage("Error", "The target process has exited. Please select another process.");
                    return;
                }

                var _ = targetProcess.ProcessName;
            }
            catch (Exception ex)
            {
                SetStatus($"Cannot access process: {ex.Message}", Colors.Red);
                ShowMessage("Access Error",
                    $"Cannot access process '{selected.Name}' (PID: {selected.ProcessId}).\n" +
                    $"Error: {ex.Message}\n\n" +
                    "Try running this application as Administrator.");
                return;
            }

            SetInjectionState(false);
            SetStatus("Injecting... Please wait", Colors.Orange);

            bool success = false;
            string resultMessage = "";
            Color resultColor = Colors.Red;

            try
            {
                var result = await Task.Run(() => PerformInjection(targetProcess, dllPath));
                success = result.Success;
                resultMessage = result.Message;
                resultColor = result.Success ? Colors.LimeGreen : Colors.Red;
            }
            catch (Exception ex)
            {
                resultMessage = $"Unexpected error: {ex.Message}";
                success = false;
                resultColor = Colors.Red;
            }
            finally
            {
                targetProcess?.Dispose();
                SetInjectionState(true);
            }

            SetStatus(resultMessage, resultColor);

            if (success)
            {
                PlaySuccessAnimation();
                ShowMessage("Success", "DLL injected successfully!");
            }
            else
            {
                PlayErrorAnimation();
            }
        }

        private (bool Success, string Message) PerformInjection(Process process, string dllPath)
        {
            try
            {
                byte[] dllBytes;
                try
                {
                    dllBytes = File.ReadAllBytes(dllPath);
                    if (dllBytes.Length == 0)
                        return (false, "DLL file is empty");
                }
                catch (Exception ex)
                {
                    return (false, $"Cannot read DLL file: {ex.Message}");
                }

                string assemblyName = "Unknown";
                try
                {
                    var asmName = AssemblyName.GetAssemblyName(dllPath);
                    assemblyName = asmName.Name;
                }
                catch { }

                Injector injector;
                try
                {
                    injector = new Injector(process.Id);
                }
                catch (Exception ex)
                {
                    return (false, $"Cannot create injector: {ex.Message}\nMake sure the target is a Mono/.NET process.");
                }

                using (injector)
                {
                    var methods = new List<(string Namespace, string Class, string Method)>
            {
                ("Loading", "Loader", "Load"),
                ("", "Loader", "Load"),
                ("Test", "Main", "Initialize"),
                ("Loader", "Main", "Start"),
                ("Inject", "Entry", "Run"),
                ("r.e.p.o_cheat", "Loader", "Init"),
            };

                    foreach (var method in methods)
                    {
                        try
                        {
                            injector.Inject(
                                dllBytes,
                                method.Namespace,
                                method.Class,
                                method.Method
                            );
                            return (true, $"Injected {assemblyName} successfully!");
                        }
                        catch (InjectorException ex)
                        {
                            Debug.WriteLine($"Injection attempt failed with {method.Namespace}.{method.Class}.{method.Method}: {ex.Message}");
                        }
                    }

                    try
                    {
                        var assembly = Assembly.Load(dllBytes);
                        var entryClass = assembly.GetTypes()
                            .FirstOrDefault(t => t.GetMethods().Any(m =>
                                m.IsStatic &&
                                m.GetParameters().Length == 0 &&
                                m.ReturnType == typeof(void)));

                        if (entryClass != null)
                        {
                            var entryMethod = entryClass.GetMethods().FirstOrDefault(m => m.IsStatic && m.GetParameters().Length == 0 && m.ReturnType == typeof(void));

                            if (entryMethod != null)
                            {
                                injector.Inject(
                                    dllBytes,
                                    entryClass.Namespace ?? "",
                                    entryClass.Name,
                                    entryMethod.Name
                                );
                                return (true, $"Auto-detected and injected {assemblyName}!\nUsed {entryClass.Namespace}.{entryClass.Name}.{entryMethod.Name}()");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Auto-detection failed: {ex.Message}");
                    }

                    return (false, $"Injection failed. Make sure your DLL has a public static void method with no parameters.\nTried: {string.Join(", ", methods.Select(m => $"{m.Namespace}.{m.Class}.{m.Method}()"))}");
                }
            }
            catch (InjectorException ex)
            {
                var error = ex.Message.ToLower();

                if (error.Contains("access denied") || error.Contains("privilege")) return (false, "Access denied. Run as Administrator.");

                if (error.Contains("mono") || error.Contains("clr") || error.Contains(".net")) return (false, "Target is not a Mono/.NET process.");

                if (error.Contains("not found") || error.Contains("couldn't find")) return (false, $"Couldn't find method. Check DLL structure.\nError: {ex.Message}");

                if (error.Contains("invalid")) return (false, $"Invalid DLL or method: {ex.Message}");

                return (false, $"Injection error: {ex.Message}");
            }
            catch (Exception ex)
            {
                return (false, $"Error: {ex.GetType().Name}: {ex.Message}");
            }
        }

        private void SetInjectionState(bool enabled)
        {
            Dispatcher.Invoke(() =>
            {
                InjectBtn.IsEnabled = enabled;
                RefreshBtn.IsEnabled = enabled;
                BrowseBtn.IsEnabled = enabled;
                InjectProgress.Visibility = enabled ? Visibility.Collapsed : Visibility.Visible;
            });
        }

        private void SetStatus(string message, Color color)
        {
            Dispatcher.Invoke(() =>
            {
                StatusLabel.Text = message;
                StatusLabel.Foreground = new SolidColorBrush(color);
            });
        }

        private void ShowMessage(string title, string message)
        {
            Dispatcher.Invoke(() =>
            {
                var foregroundBrush = StatusLabel.Foreground as SolidColorBrush;
                var color = foregroundBrush?.Color ?? Colors.Gray;

                MessageBox.Show(this, message, title, MessageBoxButton.OK, color == Colors.LimeGreen ? MessageBoxImage.Information : MessageBoxImage.Error);
            });
        }

        private void PlaySuccessAnimation()
        {
            Dispatcher.Invoke(() =>
            {
                var anim = new ColorAnimation
                {
                    To = Colors.LimeGreen,
                    Duration = TimeSpan.FromSeconds(0.5),
                    AutoReverse = true,
                    RepeatBehavior = new RepeatBehavior(2)
                };

                StatusLabel.Background = new SolidColorBrush(Colors.Transparent);
                StatusLabel.Background.BeginAnimation(SolidColorBrush.ColorProperty, anim);
            });
        }

        private void PlayErrorAnimation()
        {
            Dispatcher.Invoke(() =>
            {
                var anim = new ColorAnimation
                {
                    To = Colors.Red,
                    Duration = TimeSpan.FromSeconds(0.3),
                    AutoReverse = true,
                    RepeatBehavior = new RepeatBehavior(2)
                };

                StatusLabel.Background = new SolidColorBrush(Colors.Transparent);
                StatusLabel.Background.BeginAnimation(SolidColorBrush.ColorProperty, anim);
            });
        }

        private bool IsManagedAssembly(string filePath)
        {
            try
            {
                try
                {
                    var assemblyName = AssemblyName.GetAssemblyName(filePath);
                    return assemblyName != null;
                }
                catch (BadImageFormatException)
                {
                    return false;
                }
                catch (FileLoadException)
                {
                }
                catch
                {
                }

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (var br = new BinaryReader(fs))
                {
                    if (br.ReadUInt16() != 0x5A4D) return false;
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    uint peOffset = br.ReadUInt32();
                    if (peOffset < 64 || peOffset > fs.Length - 256) return false;
                    fs.Seek(peOffset, SeekOrigin.Begin);
                    if (br.ReadUInt32() != 0x00004550) return false;
                    ushort machine = br.ReadUInt16();
                    ushort numberOfSections = br.ReadUInt16();
                    uint timeDateStamp = br.ReadUInt32();
                    uint pointerToSymbolTable = br.ReadUInt32();
                    uint numberOfSymbols = br.ReadUInt32();
                    ushort sizeOfOptionalHeader = br.ReadUInt16();
                    ushort characteristics = br.ReadUInt16();
                    ushort magic = br.ReadUInt16();
                    bool is32Bit = (magic == 0x10B);
                    bool is64Bit = (magic == 0x20B);
                    if (!is32Bit && !is64Bit)return false;
                    int offsetToDataDirectories = is32Bit ? 96 : 112;
                    fs.Seek(offsetToDataDirectories - 2, SeekOrigin.Current);
                    fs.Seek(13 * 8, SeekOrigin.Current);
                    uint comDescriptorRva = br.ReadUInt32();
                    uint comDescriptorSize = br.ReadUInt32();
                    return comDescriptorRva != 0 && comDescriptorSize != 0;
                }
            }
            catch
            {
                return false;
            }
        }

        private void PathTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (!string.IsNullOrWhiteSpace(PathTextBox.Text))
                ValidateDLL(PathTextBox.Text);
        }

        private void OpenLogs_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EncrypticLoader");
                Directory.CreateDirectory(logDir);
                Process.Start("explorer.exe", logDir);
            }
            catch { }
        }

        private void RunAsAdmin_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var processInfo = new ProcessStartInfo
                {
                    FileName = Process.GetCurrentProcess().MainModule.FileName,
                    UseShellExecute = true,
                    Verb = "runas"
                };

                Process.Start(processInfo);
                Application.Current.Shutdown();
            }
            catch
            {
                MessageBox.Show("Failed to restart as Administrator. Please right-click and select 'Run as Administrator'.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}