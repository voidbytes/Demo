/*

使用opencv430构造

*/
#include<stdio.h>
#include<opencv2/opencv.hpp>
#include<string>
#include<vector>
#include<Windows.h>
using namespace std;
using namespace cv;

int main()
{
    VideoCapture video;
    Mat frame, gray;
    string filePath;
    cout << "请输入视频文件名，例如 a.mp4" << endl;
    cin>>filePath;
    video.open(filePath);
    if (!video.isOpened())
    {
        cout << "出现错误" << endl;
        system("pause");
        return 1;

    }
    int cols = video.get(CAP_PROP_FRAME_WIDTH);
    int rows = video.get(CAP_PROP_FRAME_HEIGHT);
    
    long framecount = static_cast<long>(video.get(CAP_PROP_FRAME_COUNT));
    if (framecount <= 0)
    {
        cout << "出现错误" << endl;
        system("pause");
        return 1;

    }
       
    int fps = video.get(CAP_PROP_FPS);
   
 
    long n = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    
    vector<string> v;
    char c[] = ".,-'`:!&@#$";
    while (n++ < framecount)
    {
        if (!video.read(frame))
            break;
       
        try {
            cvtColor(frame, gray, COLOR_BGR2GRAY);
        }
        catch (cv::Exception & e) {
            printf("exception: %s\n", e.what());
            break;
        }
        string s;
        int value;
        int delty = 10;
        int deltx = 5;
        for (int row = 0; row < rows - delty; row = row + delty)
        {

            for (int col = 0; col < cols - deltx; col = col + deltx)
            {
                value = gray.at<uchar>(row, col);
                int pos = value / 20;          
                s += c[pos];
               

            }
            s += '\n';
           

        }
        v.push_back(s);
        system("cls");
        printf("正在读取:%d%%\n", n*100/ framecount);
    }
 
    COORD  pos = { 0,0 };
    for (int i = 0; i < v.size(); i++)
    {
        SetConsoleCursorPosition(h, pos);
        cout << v[i];
        waitKey(1000 / fps);

    }
    system("pause");
    return 0;
}


