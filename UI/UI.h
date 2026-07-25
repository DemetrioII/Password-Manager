/*#pragma once
#include <QApplication>
#include <qt6/QtWidgets/QVBoxLayout>
#include <qt6/QtWidgets/QtWidgets>

class MainWindow : public QWidget {
public:
  MainWindow() {
    auto *layout = new QVBoxLayout(this);

    auto *label = new QLabel("привет!");
    auto *button = new QPushButton("нажми на меня!");

    layout->addWidget(label);
    layout->addWidget(button);

    connect(button, &QPushButton::clicked, label,
            [label]() { label->setText("Кнопка нажата!"); });

    setWindowTitle("Qt");
    resize(400, 300);
  }

  ~MainWindow() {}
};*/
